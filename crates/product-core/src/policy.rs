//! Bounded policy validation, durable intents, and mutation fences.

use crate::ffi::copy_status_text;
use crate::{
    bounded_string, ErrorCode, ProductError, ProductPolicyBundle, ProductPolicyRuleEntry,
    ProductPolicySnapshot, Status, POLICY_BUNDLE_ABI_VERSION, POLICY_BUNDLE_MAX_GATE_ENTRIES,
    POLICY_BUNDLE_MAX_L4_ENTRIES, POLICY_BUNDLE_MAX_RULE_ENTRIES,
};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

fn validate_policy_identity(bytes: &[u8]) -> Result<String, ProductError> {
    let end =
        bytes
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(|| ProductError::PolicyStore {
                detail: "policy bundle snapshot identity is not NUL terminated".to_owned(),
            })?;
    if bytes[end + 1..].iter().any(|value| *value != 0) {
        return Err(ProductError::PolicyStore {
            detail: "policy bundle snapshot identity has non-zero padding".to_owned(),
        });
    }
    let value = std::str::from_utf8(&bytes[..end]).map_err(|_| ProductError::PolicyStore {
        detail: "policy bundle snapshot identity is not UTF-8".to_owned(),
    })?;
    if value.is_empty() || value.contains(['\n', '\r', '=']) {
        return Err(ProductError::PolicyStore {
            detail: "policy bundle snapshot identity is empty or not a property value".to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn validate_policy_rule_entry(
    entry: &ProductPolicyRuleEntry,
    expected_kind: u32,
    label: &str,
) -> Result<(), ProductError> {
    let invalid = || ProductError::PolicyStore {
        detail: format!("{label} contains invalid typed rule fields"),
    };
    if entry.subject_uid == u32::MAX
        || entry.network_context == 0
        || entry.rule_kind != expected_kind
        || entry.action != PRODUCT_POLICY_ACTION_PASS_NEXT
            && entry.action != PRODUCT_POLICY_ACTION_DROP
        || entry.enabled > 1
        || entry.rule_id == 0
        || entry.reason_id == 0
        || entry.reserved != 0
    {
        return Err(invalid());
    }
    if expected_kind == PRODUCT_POLICY_RULE_KIND_GATE {
        if entry.ip_family != 0
            || entry.ip_protocol != 0
            || entry.direction != 0
            || entry.source_prefix_len != 0
            || entry.destination_prefix_len != 0
            || entry.source_port_first != 0
            || entry.source_port_last != 0
            || entry.destination_port_first != 0
            || entry.destination_port_last != 0
            || entry.priority != 0
            || entry.order != 0
            || entry.source_address.iter().any(|value| *value != 0)
            || entry.destination_address.iter().any(|value| *value != 0)
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if entry.ip_family != PRODUCT_POLICY_IP_FAMILY_IPV4
        && entry.ip_family != PRODUCT_POLICY_IP_FAMILY_IPV6
    {
        return Err(invalid());
    }
    if entry.ip_family == PRODUCT_POLICY_IP_FAMILY_IPV4
        && (entry.source_address[4..].iter().any(|value| *value != 0)
            || entry.destination_address[4..]
                .iter()
                .any(|value| *value != 0))
    {
        return Err(invalid());
    }
    if entry.ip_protocol != PRODUCT_POLICY_IP_PROTOCOL_TCP
        && entry.ip_protocol != PRODUCT_POLICY_IP_PROTOCOL_UDP
    {
        return Err(invalid());
    }
    if entry.direction != PRODUCT_POLICY_DIRECTION_INPUT
        && entry.direction != PRODUCT_POLICY_DIRECTION_OUTPUT
    {
        return Err(invalid());
    }
    let max_prefix = if entry.ip_family == PRODUCT_POLICY_IP_FAMILY_IPV4 {
        32
    } else {
        128
    };
    if entry.source_prefix_len > max_prefix
        || entry.destination_prefix_len > max_prefix
        || entry.source_port_first > entry.source_port_last
        || entry.destination_port_first > entry.destination_port_last
        || entry.source_port_last > u16::MAX as u32
        || entry.destination_port_last > u16::MAX as u32
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn validate_policy_bundle(bundle: &ProductPolicyBundle) -> Result<String, ProductError> {
    if bundle.abi_version != POLICY_BUNDLE_ABI_VERSION
        || bundle.struct_size as usize != std::mem::size_of::<ProductPolicyBundle>()
        || bundle.requested_revision == 0
        || bundle.snapshot_hash == 0
        || bundle.gate_entry_count as usize > POLICY_BUNDLE_MAX_GATE_ENTRIES
        || bundle.l4_rule_count as usize > POLICY_BUNDLE_MAX_L4_ENTRIES
        || (bundle.gate_entry_count as usize)
            .checked_add(bundle.l4_rule_count as usize)
            .is_none_or(|count| count > POLICY_BUNDLE_MAX_RULE_ENTRIES)
        || bundle.default_pass > 1
        || bundle.reserved != 0
    {
        return Err(ProductError::PolicyStore {
            detail: "policy bundle header or bounded counts are invalid".to_owned(),
        });
    }
    let identity = validate_policy_identity(&bundle.snapshot_identity)?;
    let mut rule_ids = HashSet::new();
    for (index, entry) in bundle.gate_entries.iter().enumerate() {
        if index < bundle.gate_entry_count as usize {
            validate_policy_rule_entry(
                entry,
                PRODUCT_POLICY_RULE_KIND_GATE,
                &format!("policy bundle Gate entry {index}"),
            )?;
            if !rule_ids.insert(entry.rule_id) {
                return Err(ProductError::PolicyStore {
                    detail: format!("policy bundle duplicate stable rule ID at Gate entry {index}"),
                });
            }
        } else if *entry != ProductPolicyRuleEntry::zeroed() {
            return Err(ProductError::PolicyStore {
                detail: format!("policy bundle unused Gate entry {index} is non-zero"),
            });
        }
    }
    for (index, entry) in bundle.l4_entries.iter().enumerate() {
        if index < bundle.l4_rule_count as usize {
            validate_policy_rule_entry(
                entry,
                PRODUCT_POLICY_RULE_KIND_L4,
                &format!("policy bundle L4 entry {index}"),
            )?;
            if !rule_ids.insert(entry.rule_id) {
                return Err(ProductError::PolicyStore {
                    detail: format!("policy bundle duplicate stable rule ID at L4 entry {index}"),
                });
            }
        } else if *entry != ProductPolicyRuleEntry::zeroed() {
            return Err(ProductError::PolicyStore {
                detail: format!("policy bundle unused L4 entry {index} is non-zero"),
            });
        }
    }
    Ok(identity)
}

const EMPTY_POLICY_STORE_DIR: &str = "product-policy";
const POLICY_BUNDLE_STORE_FILE: &str = "policy-bundle.properties";
const POLICY_BUNDLE_STORE_TEMP_FILE: &str = "policy-bundle.properties.tmp";
const POLICY_BUNDLE_STORE_SCHEMA: &str = "sakamoto-policy-bundle/v1";
pub(super) const EMPTY_POLICY_STORE_FILE: &str = "empty-intent.properties";
const EMPTY_POLICY_STORE_TEMP_FILE: &str = "empty-intent.properties.tmp";
const EMPTY_POLICY_STORE_SCHEMA: &str = "sakamoto-empty-policy-intent/v1";
pub(super) const NETWORK_GATE_POLICY_STORE_FILE: &str = "network-gate-intent.properties";
const NETWORK_GATE_POLICY_STORE_TEMP_FILE: &str = "network-gate-intent.properties.tmp";
const NETWORK_GATE_POLICY_STORE_SCHEMA: &str = "sakamoto-network-gate-policy-intent/v1";
pub(super) const L4_POLICY_STORE_FILE: &str = "l4-intent.properties";
const L4_POLICY_STORE_TEMP_FILE: &str = "l4-intent.properties.tmp";
const L4_POLICY_STORE_SCHEMA: &str = "sakamoto-l4-policy-intent/v1";
const POLICY_MUTATION_FENCE_FILE: &str = "policy-mutation-fence.properties";
const POLICY_MUTATION_FENCE_TEMP_FILE: &str = "policy-mutation-fence.properties.tmp";
const POLICY_MUTATION_CANDIDATE_FILE: &str = "policy-mutation-candidate.properties";
const POLICY_MUTATION_FENCE_SCHEMA: &str = "sakamoto-policy-mutation-fence/v2";
const POLICY_MUTATION_FENCE_STATE_UNKNOWN: &str = "unknown";
const EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const PRODUCT_L4_IP_FAMILY_IPV4: u32 = 4;
const PRODUCT_L4_IP_PROTOCOL_TCP: u32 = 6;
const PRODUCT_L4_DIRECTION_INPUT: u32 = 1;
const PRODUCT_L4_DIRECTION_OUTPUT: u32 = 3;
const PRODUCT_L4_ACTION_PASS_NEXT: u32 = 1;
const PRODUCT_L4_ACTION_DROP: u32 = 2;
const PRODUCT_POLICY_RULE_KIND_GATE: u32 = 1;
const PRODUCT_POLICY_RULE_KIND_L4: u32 = 2;
const PRODUCT_POLICY_IP_FAMILY_IPV4: u32 = 4;
const PRODUCT_POLICY_IP_FAMILY_IPV6: u32 = 6;
const PRODUCT_POLICY_IP_PROTOCOL_TCP: u32 = 6;
const PRODUCT_POLICY_IP_PROTOCOL_UDP: u32 = 17;
const PRODUCT_POLICY_DIRECTION_INPUT: u32 = 1;
const PRODUCT_POLICY_DIRECTION_OUTPUT: u32 = 3;
const PRODUCT_POLICY_ACTION_PASS_NEXT: u32 = 1;
const PRODUCT_POLICY_ACTION_DROP: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EmptyPolicySnapshot {
    revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
}

impl EmptyPolicySnapshot {
    pub(super) fn new(revision: u64) -> Result<Self, ProductError> {
        if revision == 0 {
            return Err(ProductError::PolicyStore {
                detail: "empty policy revision must be positive".to_owned(),
            });
        }
        let snapshot_identity = format!("empty-policy/v1/revision-{revision}");
        let material = format!(
            "schema=empty-policy/v1\nrevision={revision}\ndefault_pass=true\ngate_claim_count=0\nl4_rule_count=0\n"
        );
        let snapshot_hash = fnv1a64(material.as_bytes());
        Ok(Self {
            revision,
            snapshot_hash,
            snapshot_identity,
        })
    }

    pub(super) fn to_ffi(&self) -> ProductPolicySnapshot {
        let mut snapshot = ProductPolicySnapshot::zeroed();
        snapshot.schema_version = EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION;
        snapshot.requested_revision = self.revision;
        snapshot.snapshot_hash = self.snapshot_hash;
        snapshot.snapshot_empty = 1;
        snapshot.default_pass = 1;
        snapshot.gate_claim_count = 0;
        snapshot.l4_rule_count = 0;
        snapshot.gate_subject_uid = 0;
        snapshot.gate_network_context = 0;
        snapshot.gate_blocked = 0;
        snapshot.gate_reason_id = 0;
        snapshot.gate_rule_id = 0;
        copy_status_text(&mut snapshot.snapshot_identity, &self.snapshot_identity);
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct NetworkGatePolicySnapshot {
    revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
    subject_uid: u32,
    network_context: u32,
    blocked: bool,
    rule_id: u64,
    reason_id: u32,
}

impl NetworkGatePolicySnapshot {
    pub(super) fn new(
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Self, ProductError> {
        if revision == 0
            || subject_uid == u32::MAX
            || network_context == 0
            || rule_id == 0
            || reason_id == 0
        {
            return Err(ProductError::PolicyStore {
                detail: "network gate policy snapshot fields are invalid".to_owned(),
            });
        }
        let state = if blocked { "blocked" } else { "open" };
        let snapshot_identity = format!(
            "network-gate/v1/revision-{revision}/uid-{subject_uid}/context-{network_context}/{state}"
        );
        let material = format!(
            "schema=network-gate/v1\nrevision={revision}\ndefault_pass=true\ngate_claim_count={}\nl4_rule_count=0\nsubject_uid={subject_uid}\nnetwork_context={network_context}\nblocked={blocked}\nrule_id={rule_id}\nreason_id={reason_id}\n",
            if blocked { 1 } else { 0 }
        );
        let snapshot_hash = fnv1a64(material.as_bytes());
        Ok(Self {
            revision,
            snapshot_hash,
            snapshot_identity,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        })
    }

    pub(super) fn to_ffi(&self) -> ProductPolicySnapshot {
        let mut snapshot = ProductPolicySnapshot::zeroed();
        snapshot.schema_version = EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION;
        snapshot.requested_revision = self.revision;
        snapshot.snapshot_hash = self.snapshot_hash;
        snapshot.snapshot_empty = 0;
        snapshot.default_pass = 1;
        snapshot.gate_claim_count = if self.blocked { 1 } else { 0 };
        snapshot.l4_rule_count = 0;
        snapshot.gate_subject_uid = self.subject_uid;
        snapshot.gate_network_context = self.network_context;
        snapshot.gate_blocked = u32::from(self.blocked);
        snapshot.gate_reason_id = self.reason_id;
        snapshot.gate_rule_id = self.rule_id;
        copy_status_text(&mut snapshot.snapshot_identity, &self.snapshot_identity);
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ipv4Cidr {
    text: String,
    address: [u8; 16],
    prefix_len: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StatelessL4PolicySnapshot {
    revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
    subject_uid: u32,
    network_context: u32,
    ip_family: u32,
    ip_protocol: u32,
    direction: u32,
    action: u32,
    source: Ipv4Cidr,
    destination: Ipv4Cidr,
    source_port_first: u32,
    source_port_last: u32,
    destination_port_first: u32,
    destination_port_last: u32,
    priority: u32,
    order: u32,
    rule_id: u64,
    reason_id: u32,
}

impl StatelessL4PolicySnapshot {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Self, ProductError> {
        if revision == 0
            || subject_uid == u32::MAX
            || network_context == 0
            || ip_family != PRODUCT_L4_IP_FAMILY_IPV4
            || ip_protocol != PRODUCT_L4_IP_PROTOCOL_TCP
            || !matches!(
                direction,
                PRODUCT_L4_DIRECTION_INPUT | PRODUCT_L4_DIRECTION_OUTPUT
            )
            || !matches!(action, PRODUCT_L4_ACTION_PASS_NEXT | PRODUCT_L4_ACTION_DROP)
            || source_port_first > source_port_last
            || destination_port_first > destination_port_last
            || source_port_last > u16::MAX as u32
            || destination_port_last > u16::MAX as u32
            || rule_id == 0
            || reason_id == 0
        {
            return Err(ProductError::PolicyStore {
                detail: "stateless L4 policy snapshot fields are invalid".to_owned(),
            });
        }
        let source = parse_ipv4_cidr(source_cidr, "stateless L4 source CIDR")?;
        let destination = parse_ipv4_cidr(destination_cidr, "stateless L4 destination CIDR")?;
        let action_name = match action {
            PRODUCT_L4_ACTION_DROP => "drop",
            _ => "allow",
        };
        let snapshot_identity = format!(
            "l4tcp4/1/revision-{revision}/uid-{subject_uid}/context-{network_context}/rule-{rule_id}/{action_name}"
        );
        let material = format!(
            "schema=l4tcp4/1\nrevision={revision}\ndefault_pass=true\ngate_claim_count=0\nl4_rule_count=1\nsubject_uid={subject_uid}\nnetwork_context={network_context}\nip_family={ip_family}\nip_protocol={ip_protocol}\ndirection={direction}\naction={action}\nsource_cidr={}\ndestination_cidr={}\nsource_port_first={source_port_first}\nsource_port_last={source_port_last}\ndestination_port_first={destination_port_first}\ndestination_port_last={destination_port_last}\npriority={priority}\norder={order}\nrule_id={rule_id}\nreason_id={reason_id}\n",
            source.text, destination.text
        );
        let snapshot_hash = fnv1a64(material.as_bytes());
        Ok(Self {
            revision,
            snapshot_hash,
            snapshot_identity,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source,
            destination,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        })
    }

    pub(super) fn to_ffi(&self) -> ProductPolicySnapshot {
        let mut snapshot = ProductPolicySnapshot::zeroed();
        snapshot.schema_version = EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION;
        snapshot.requested_revision = self.revision;
        snapshot.snapshot_hash = self.snapshot_hash;
        snapshot.snapshot_empty = 0;
        snapshot.default_pass = 1;
        snapshot.gate_claim_count = 0;
        snapshot.l4_rule_count = 1;
        snapshot.gate_subject_uid = 0;
        snapshot.gate_network_context = 0;
        snapshot.gate_blocked = 0;
        snapshot.gate_reason_id = 0;
        snapshot.gate_rule_id = 0;
        snapshot.l4_subject_uid = self.subject_uid;
        snapshot.l4_network_context = self.network_context;
        snapshot.l4_ip_family = self.ip_family;
        snapshot.l4_ip_protocol = self.ip_protocol;
        snapshot.l4_direction = self.direction;
        snapshot.l4_action = self.action;
        snapshot.l4_source_prefix_len = self.source.prefix_len;
        snapshot.l4_destination_prefix_len = self.destination.prefix_len;
        snapshot.l4_source_port_first = self.source_port_first;
        snapshot.l4_source_port_last = self.source_port_last;
        snapshot.l4_destination_port_first = self.destination_port_first;
        snapshot.l4_destination_port_last = self.destination_port_last;
        snapshot.l4_priority = self.priority;
        snapshot.l4_order = self.order;
        snapshot.l4_reason_id = self.reason_id;
        snapshot.l4_rule_id = self.rule_id;
        snapshot.l4_source_address = self.source.address;
        snapshot.l4_destination_address = self.destination.address;
        copy_status_text(&mut snapshot.snapshot_identity, &self.snapshot_identity);
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RuntimePolicySnapshot {
    Empty(EmptyPolicySnapshot),
    NetworkGate(NetworkGatePolicySnapshot),
    StatelessL4(StatelessL4PolicySnapshot),
    Bundle(ProductPolicyBundle),
}

impl RuntimePolicySnapshot {
    fn revision(&self) -> u64 {
        match self {
            Self::Empty(snapshot) => snapshot.revision,
            Self::NetworkGate(snapshot) => snapshot.revision,
            Self::StatelessL4(snapshot) => snapshot.revision,
            Self::Bundle(snapshot) => snapshot.requested_revision,
        }
    }

    pub(super) fn to_ffi(&self) -> ProductPolicySnapshot {
        match self {
            Self::Empty(snapshot) => snapshot.to_ffi(),
            Self::NetworkGate(snapshot) => snapshot.to_ffi(),
            Self::StatelessL4(snapshot) => snapshot.to_ffi(),
            Self::Bundle(_) => {
                panic!("complete policy bundle must use the bundle native apply path")
            }
        }
    }

    pub(super) fn bundle(&self) -> Option<&ProductPolicyBundle> {
        match self {
            Self::Bundle(bundle) => Some(bundle),
            _ => None,
        }
    }

    pub(super) fn target_file(&self) -> &'static str {
        match self {
            Self::Empty(_) => EMPTY_POLICY_STORE_FILE,
            Self::NetworkGate(_) => NETWORK_GATE_POLICY_STORE_FILE,
            Self::StatelessL4(_) => L4_POLICY_STORE_FILE,
            Self::Bundle(_) => POLICY_BUNDLE_STORE_FILE,
        }
    }
}

/*
 * A mutation fence is the durable hand-off between a VAPI request that may
 * have reached VPP and the next Product Core generation.  It is deliberately
 * a small properties record rather than an ABI extension: ProductStatus keeps
 * its fixed layout, while the revision/hash/identity tuple remains available
 * across a process death.  The fence is written only for an ambiguous,
 * post-submit policy outcome and is cleared only after fresh-generation
 * readback (never by a delayed reply on the fenced generation).
 */
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PolicyMutationFence {
    pub(super) generation: u64,
    predecessor_generation: u64,
    predecessor_revision: u64,
    predecessor_hash: u64,
    pub(super) requested_revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
    artifact_id: String,
    api_identity: String,
    pub(super) operation_id: String,
    pub(super) target_file: String,
}

fn valid_mutation_fence_identity(value: &str) -> bool {
    !value.is_empty() && value.len() < 96 && !value.contains(['\n', '\r', '='])
}

impl PolicyMutationFence {
    pub(super) fn for_snapshot(
        generation: u64,
        predecessor: &Status,
        snapshot: &ProductPolicySnapshot,
        target_file: &str,
    ) -> Result<Self, ProductError> {
        let snapshot_identity = bounded_string(&snapshot.snapshot_identity);
        let artifact_id = predecessor.artifact_id.clone();
        let api_identity = predecessor.api_identity.clone();
        if generation == 0
            || snapshot.requested_revision == 0
            || snapshot.snapshot_hash == 0
            || !valid_mutation_fence_identity(&snapshot_identity)
            || !valid_mutation_fence_identity(&artifact_id)
            || !valid_mutation_fence_identity(&api_identity)
            || !matches!(
                target_file,
                POLICY_BUNDLE_STORE_FILE
                    | EMPTY_POLICY_STORE_FILE
                    | NETWORK_GATE_POLICY_STORE_FILE
                    | L4_POLICY_STORE_FILE
            )
        {
            return Err(ProductError::PolicyStore {
                detail: "unknown policy outcome has no complete mutation identity".to_owned(),
            });
        }
        let operation_id = format!(
            "policy-snapshot/v1/revision-{}/hash-{}",
            snapshot.requested_revision, snapshot.snapshot_hash
        );
        Ok(Self {
            generation,
            predecessor_generation: predecessor.generation,
            predecessor_revision: predecessor.policy_active_revision,
            predecessor_hash: predecessor.policy_snapshot_hash,
            requested_revision: snapshot.requested_revision,
            snapshot_hash: snapshot.snapshot_hash,
            snapshot_identity,
            artifact_id,
            api_identity,
            operation_id,
            target_file: target_file.to_owned(),
        })
    }

    pub(super) fn for_bundle(
        generation: u64,
        predecessor: &Status,
        bundle: &ProductPolicyBundle,
    ) -> Result<Self, ProductError> {
        let snapshot_identity = bounded_string(&bundle.snapshot_identity);
        let artifact_id = predecessor.artifact_id.clone();
        let api_identity = predecessor.api_identity.clone();
        if generation == 0
            || bundle.requested_revision == 0
            || bundle.snapshot_hash == 0
            || !valid_mutation_fence_identity(&snapshot_identity)
            || !valid_mutation_fence_identity(&artifact_id)
            || !valid_mutation_fence_identity(&api_identity)
        {
            return Err(ProductError::PolicyStore {
                detail: "unknown policy outcome has no complete mutation identity".to_owned(),
            });
        }
        let operation_id = format!(
            "policy-bundle/v1/revision-{}/hash-{}",
            bundle.requested_revision, bundle.snapshot_hash
        );
        Ok(Self {
            generation,
            predecessor_generation: predecessor.generation,
            predecessor_revision: predecessor.policy_active_revision,
            predecessor_hash: predecessor.policy_snapshot_hash,
            requested_revision: bundle.requested_revision,
            snapshot_hash: bundle.snapshot_hash,
            snapshot_identity,
            artifact_id,
            api_identity,
            operation_id,
            target_file: POLICY_BUNDLE_STORE_FILE.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProductPolicyStore {
    files_dir: PathBuf,
}

impl ProductPolicyStore {
    pub(super) fn new(files_dir: &Path) -> Self {
        Self {
            files_dir: files_dir.to_path_buf(),
        }
    }

    pub(super) fn current_mutation_fence(
        &self,
    ) -> Result<Option<PolicyMutationFence>, ProductError> {
        let path = self.mutation_fence_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let metadata = fs::metadata(&path).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation fence metadata could not be read: {error}"),
        })?;
        if metadata.len() > 4096 {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence exceeds its bounded record size".to_owned(),
            });
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("policy mutation fence could not be read: {error}"),
            })?;
        if property_value(&text, "schema").unwrap_or_default() != POLICY_MUTATION_FENCE_SCHEMA
            || property_value(&text, "state").unwrap_or_default()
                != POLICY_MUTATION_FENCE_STATE_UNKNOWN
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence schema or state is unsupported".to_owned(),
            });
        }
        let target_file = required_string_property(&text, "targetFile", "policy mutation fence")?;
        if target_file != POLICY_BUNDLE_STORE_FILE
            && target_file != EMPTY_POLICY_STORE_FILE
            && target_file != NETWORK_GATE_POLICY_STORE_FILE
            && target_file != L4_POLICY_STORE_FILE
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence target is unsupported".to_owned(),
            });
        }
        let candidate_file =
            required_string_property(&text, "candidateFile", "policy mutation fence")?;
        if candidate_file != POLICY_MUTATION_CANDIDATE_FILE {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence candidate is unsupported".to_owned(),
            });
        }
        let snapshot_identity =
            required_string_property(&text, "snapshotIdentity", "policy mutation fence")?;
        if snapshot_identity.len() >= 96 || snapshot_identity.contains(['\n', '\r', '=']) {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence identity is invalid".to_owned(),
            });
        }
        let artifact_id = required_string_property(&text, "artifactId", "policy mutation fence")?;
        let api_identity = required_string_property(&text, "apiIdentity", "policy mutation fence")?;
        if !valid_mutation_fence_identity(&artifact_id)
            || !valid_mutation_fence_identity(&api_identity)
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence artifact/API identity is invalid".to_owned(),
            });
        }
        let operation_id = required_string_property(&text, "operationId", "policy mutation fence")?;
        if operation_id.len() > 255 || operation_id.contains(['\n', '\r', '=']) {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence operation identity is invalid".to_owned(),
            });
        }
        Ok(Some(PolicyMutationFence {
            generation: required_u64_property(&text, "generation", "policy mutation fence")?,
            predecessor_generation: optional_u64_property(
                &text,
                "predecessorGeneration",
                "policy mutation fence",
            )?,
            predecessor_revision: optional_u64_property(
                &text,
                "predecessorRevision",
                "policy mutation fence",
            )?,
            predecessor_hash: optional_u64_property(
                &text,
                "predecessorHash",
                "policy mutation fence",
            )?,
            requested_revision: required_u64_property(
                &text,
                "requestedRevision",
                "policy mutation fence",
            )?,
            snapshot_hash: required_u64_property(&text, "snapshotHash", "policy mutation fence")?,
            snapshot_identity,
            artifact_id,
            api_identity,
            operation_id,
            target_file,
        }))
    }

    pub(super) fn has_unresolved_mutation_artifact(&self) -> bool {
        [
            self.mutation_candidate_state_file(),
            self.mutation_fence_temp_state_file(),
            self.state_dir().join(POLICY_BUNDLE_STORE_TEMP_FILE),
            self.state_dir().join(EMPTY_POLICY_STORE_TEMP_FILE),
            self.state_dir().join(NETWORK_GATE_POLICY_STORE_TEMP_FILE),
            self.state_dir().join(L4_POLICY_STORE_TEMP_FILE),
        ]
        .iter()
        .any(|path| path.is_file())
    }

    pub(super) fn write_mutation_fence(
        &self,
        fence: &PolicyMutationFence,
    ) -> Result<(), ProductError> {
        if fence.generation == 0
            || fence.requested_revision == 0
            || fence.snapshot_hash == 0
            || !valid_mutation_fence_identity(&fence.snapshot_identity)
            || !valid_mutation_fence_identity(&fence.artifact_id)
            || !valid_mutation_fence_identity(&fence.api_identity)
            || fence.operation_id.is_empty()
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence identity is incomplete".to_owned(),
            });
        }
        if fence.operation_id.len() > 255 || fence.operation_id.contains(['\n', '\r', '=']) {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence identity is not bounded".to_owned(),
            });
        }
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation fence directory could not be created: {error}"),
        })?;
        let temporary = directory.join(POLICY_MUTATION_FENCE_TEMP_FILE);
        let target = self.mutation_fence_state_file();
        let text = format!(
            "schema={POLICY_MUTATION_FENCE_SCHEMA}\nstate={POLICY_MUTATION_FENCE_STATE_UNKNOWN}\ngeneration={}\npredecessorGeneration={}\npredecessorRevision={}\npredecessorHash={}\nrequestedRevision={}\nsnapshotHash={}\nsnapshotIdentity={}\nartifactId={}\napiIdentity={}\noperationId={}\ntargetFile={}\ncandidateFile={}\n",
            fence.generation,
            fence.predecessor_generation,
            fence.predecessor_revision,
            fence.predecessor_hash,
            fence.requested_revision,
            fence.snapshot_hash,
            fence.snapshot_identity,
            fence.artifact_id,
            fence.api_identity,
            fence.operation_id,
            fence.target_file,
            POLICY_MUTATION_CANDIDATE_FILE,
        );
        if text.len() > 4096 {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence record is too large".to_owned(),
            });
        }
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("policy mutation fence temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("policy mutation fence could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation fence could not be published: {error}"),
        })
    }

    pub(super) fn clear_mutation_fence(&self) -> Result<(), ProductError> {
        match fs::remove_file(self.mutation_fence_state_file()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("policy mutation fence could not be cleared: {error}"),
            }),
        }
    }

    pub(super) fn quarantine_policy_bundle(&self, temporary: &Path) -> Result<(), ProductError> {
        fs::rename(temporary, self.mutation_candidate_state_file()).map_err(|error| {
            ProductError::PolicyStore {
                detail: format!("unknown policy bundle could not be retained: {error}"),
            }
        })
    }

    pub(super) fn quarantine_persisted_intent(
        &self,
        target_file: &str,
    ) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        if !target.is_file() {
            return Err(ProductError::PolicyStore {
                detail: "persisted policy intent disappeared before reconcile".to_owned(),
            });
        }
        let candidate = self.mutation_candidate_state_file();
        if candidate.exists() {
            return Err(ProductError::PolicyStore {
                detail: "orphaned policy mutation candidate blocks reconcile".to_owned(),
            });
        }
        fs::rename(&target, &candidate).map_err(|error| ProductError::PolicyStore {
            detail: format!("persisted policy intent could not be retained: {error}"),
        })
    }

    pub(super) fn restore_mutation_candidate(&self, target_file: &str) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        if !self.mutation_candidate_state_file().is_file() {
            return Ok(());
        }
        fs::rename(self.mutation_candidate_state_file(), &target).map_err(|error| {
            ProductError::PolicyStore {
                detail: format!("persisted policy intent could not be restored: {error}"),
            }
        })
    }

    pub(super) fn validate_mutation_candidate(
        &self,
        fence: &PolicyMutationFence,
    ) -> Result<(), ProductError> {
        let path = self.mutation_candidate_state_file();
        if !path.is_file() {
            return Err(ProductError::PolicyStore {
                detail: "unknown policy candidate is missing during readback".to_owned(),
            });
        }
        let metadata = fs::metadata(&path).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation candidate metadata could not be read: {error}"),
        })?;
        if metadata.len() > 64 * 1024 {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation candidate exceeds its bounded size".to_owned(),
            });
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("policy mutation candidate could not be read: {error}"),
            })?;
        let revision = required_u64_property(&text, "revision", "policy mutation candidate")?;
        let snapshot_hash =
            required_u64_property(&text, "snapshotHash", "policy mutation candidate")?;
        let snapshot_identity =
            required_string_property(&text, "snapshotIdentity", "policy mutation candidate")?;
        if revision != fence.requested_revision
            || snapshot_hash != fence.snapshot_hash
            || snapshot_identity != fence.snapshot_identity
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation candidate identity does not match its fence".to_owned(),
            });
        }
        Ok(())
    }

    pub(super) fn promote_mutation_candidate(&self, target_file: &str) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        fs::rename(self.mutation_candidate_state_file(), &target).map_err(|error| {
            ProductError::PolicyStore {
                detail: format!("reconciled policy candidate could not be published: {error}"),
            }
        })?;
        self.remove_other_policy_intents(target_file)
    }

    pub(super) fn discard_mutation_candidate(&self) {
        let _ = fs::remove_file(self.mutation_candidate_state_file());
    }

    pub(super) fn current_snapshot(&self) -> Result<Option<RuntimePolicySnapshot>, ProductError> {
        /* A bundle is the only authoritative v1 successor.  Compatibility
         * intents are consulted only when no bundle exists, never merged with
         * a bundle or with one another. */
        if let Some(bundle) = self.current_policy_bundle()? {
            return Ok(Some(RuntimePolicySnapshot::Bundle(bundle)));
        }
        let mut selected = None;
        if let Some(snapshot) = self.current_empty_snapshot()? {
            selected = Some(RuntimePolicySnapshot::Empty(snapshot));
        }
        if let Some(snapshot) = self.current_network_gate_snapshot()? {
            let candidate = RuntimePolicySnapshot::NetworkGate(snapshot);
            if selected
                .as_ref()
                .map(|current| candidate.revision() >= current.revision())
                .unwrap_or(true)
            {
                selected = Some(candidate);
            }
        }
        if let Some(snapshot) = self.current_l4_snapshot()? {
            let candidate = RuntimePolicySnapshot::StatelessL4(snapshot);
            if selected
                .as_ref()
                .map(|current| candidate.revision() >= current.revision())
                .unwrap_or(true)
            {
                selected = Some(candidate);
            }
        }
        Ok(selected)
    }

    fn current_policy_bundle(&self) -> Result<Option<ProductPolicyBundle>, ProductError> {
        let path = self.policy_bundle_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("policy bundle could not be read: {error}"),
            })?;
        if property_value(&text, "schema").unwrap_or_default() != POLICY_BUNDLE_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "policy bundle schema is unsupported".to_owned(),
            });
        }
        let mut bundle = ProductPolicyBundle::zeroed();
        bundle.abi_version = required_u32_property(&text, "abiVersion", "policy bundle")?;
        bundle.struct_size = required_u32_property(&text, "structSize", "policy bundle")?;
        bundle.requested_revision = required_u64_property(&text, "revision", "policy bundle")?;
        bundle.snapshot_hash = required_u64_property(&text, "snapshotHash", "policy bundle")?;
        bundle.gate_entry_count = required_u32_property(&text, "gateEntryCount", "policy bundle")?;
        bundle.l4_rule_count = required_u32_property(&text, "l4RuleCount", "policy bundle")?;
        bundle.default_pass = required_u32_property(&text, "defaultPass", "policy bundle")?;
        bundle.snapshot_identity = fixed_text_property(&text, "snapshotIdentity", "policy bundle")?;
        for index in 0..(bundle.gate_entry_count as usize).min(POLICY_BUNDLE_MAX_GATE_ENTRIES) {
            bundle.gate_entries[index] =
                parse_policy_rule_entry(&text, "gate", index, PRODUCT_POLICY_RULE_KIND_GATE)?;
        }
        for index in 0..(bundle.l4_rule_count as usize).min(POLICY_BUNDLE_MAX_L4_ENTRIES) {
            bundle.l4_entries[index] =
                parse_policy_rule_entry(&text, "l4", index, PRODUCT_POLICY_RULE_KIND_L4)?;
        }
        validate_policy_bundle(&bundle)?;
        Ok(Some(bundle))
    }

    fn current_empty_snapshot(&self) -> Result<Option<EmptyPolicySnapshot>, ProductError> {
        let path = self.state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("empty policy intent could not be read: {error}"),
            })?;
        let schema = property_value(&text, "schema").unwrap_or_default();
        if schema != EMPTY_POLICY_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "empty policy intent schema is unsupported".to_owned(),
            });
        }
        let revision = property_value(&text, "revision")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|revision| *revision != 0)
            .ok_or_else(|| ProductError::PolicyStore {
                detail: "empty policy intent revision is invalid".to_owned(),
            })?;
        Ok(Some(EmptyPolicySnapshot::new(revision)?))
    }

    fn current_network_gate_snapshot(
        &self,
    ) -> Result<Option<NetworkGatePolicySnapshot>, ProductError> {
        let path = self.network_gate_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("network gate policy intent could not be read: {error}"),
            })?;
        let schema = property_value(&text, "schema").unwrap_or_default();
        if schema != NETWORK_GATE_POLICY_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "network gate policy intent schema is unsupported".to_owned(),
            });
        }
        let revision = required_u64_property(&text, "revision", "network gate policy")?;
        let subject_uid = required_u32_property(&text, "subjectUid", "network gate policy")?;
        let network_context =
            required_u32_property(&text, "networkContext", "network gate policy")?;
        let blocked = required_bool_property(&text, "blocked", "network gate policy")?;
        let rule_id = required_u64_property(&text, "ruleId", "network gate policy")?;
        let reason_id = required_u32_property(&text, "reasonId", "network gate policy")?;
        Ok(Some(NetworkGatePolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?))
    }

    fn current_l4_snapshot(&self) -> Result<Option<StatelessL4PolicySnapshot>, ProductError> {
        let path = self.l4_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("stateless L4 policy intent could not be read: {error}"),
            })?;
        let schema = property_value(&text, "schema").unwrap_or_default();
        if schema != L4_POLICY_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "stateless L4 policy intent schema is unsupported".to_owned(),
            });
        }
        let revision = required_u64_property(&text, "revision", "stateless L4 policy")?;
        let subject_uid = required_u32_property(&text, "subjectUid", "stateless L4 policy")?;
        let network_context =
            required_u32_property(&text, "networkContext", "stateless L4 policy")?;
        let ip_family = required_u32_property(&text, "ipFamily", "stateless L4 policy")?;
        let ip_protocol = required_u32_property(&text, "ipProtocol", "stateless L4 policy")?;
        let direction = required_u32_property(&text, "direction", "stateless L4 policy")?;
        let action = required_u32_property(&text, "action", "stateless L4 policy")?;
        let source_cidr = property_value(&text, "sourceCidr").unwrap_or_else(|| "0.0.0.0/0".into());
        let destination_cidr =
            property_value(&text, "destinationCidr").unwrap_or_else(|| "0.0.0.0/0".into());
        let source_port_first =
            required_u32_property(&text, "sourcePortFirst", "stateless L4 policy")?;
        let source_port_last =
            required_u32_property(&text, "sourcePortLast", "stateless L4 policy")?;
        let destination_port_first =
            required_u32_property(&text, "destinationPortFirst", "stateless L4 policy")?;
        let destination_port_last =
            required_u32_property(&text, "destinationPortLast", "stateless L4 policy")?;
        let priority = required_u32_property(&text, "priority", "stateless L4 policy")?;
        let order = required_u32_property(&text, "order", "stateless L4 policy")?;
        let rule_id = required_u64_property(&text, "ruleId", "stateless L4 policy")?;
        let reason_id = required_u32_property(&text, "reasonId", "stateless L4 policy")?;
        Ok(Some(StatelessL4PolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            &source_cidr,
            &destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )?))
    }

    pub(super) fn stage_empty_snapshot(
        &self,
        snapshot: &EmptyPolicySnapshot,
    ) -> Result<PathBuf, ProductError> {
        let temporary = self.state_dir().join(EMPTY_POLICY_STORE_TEMP_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=true\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=0\n",
            EMPTY_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash
        );
        self.stage_intent_text(temporary, text, "empty policy intent")
    }

    pub(super) fn stage_network_gate_snapshot(
        &self,
        snapshot: &NetworkGatePolicySnapshot,
    ) -> Result<PathBuf, ProductError> {
        let temporary = self.state_dir().join(NETWORK_GATE_POLICY_STORE_TEMP_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount={}\nl4RuleCount=0\nsubjectUid={}\nnetworkContext={}\nblocked={}\nruleId={}\nreasonId={}\n",
            NETWORK_GATE_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            if snapshot.blocked { 1 } else { 0 },
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.blocked,
            snapshot.rule_id,
            snapshot.reason_id
        );
        self.stage_intent_text(temporary, text, "network gate policy intent")
    }

    pub(super) fn stage_l4_snapshot(
        &self,
        snapshot: &StatelessL4PolicySnapshot,
    ) -> Result<PathBuf, ProductError> {
        let temporary = self.state_dir().join(L4_POLICY_STORE_TEMP_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=1\nsubjectUid={}\nnetworkContext={}\nipFamily={}\nipProtocol={}\ndirection={}\naction={}\nsourceCidr={}\ndestinationCidr={}\nsourcePrefixLen={}\ndestinationPrefixLen={}\nsourcePortFirst={}\nsourcePortLast={}\ndestinationPortFirst={}\ndestinationPortLast={}\npriority={}\norder={}\nruleId={}\nreasonId={}\n",
            L4_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.ip_family,
            snapshot.ip_protocol,
            snapshot.direction,
            snapshot.action,
            snapshot.source.text,
            snapshot.destination.text,
            snapshot.source.prefix_len,
            snapshot.destination.prefix_len,
            snapshot.source_port_first,
            snapshot.source_port_last,
            snapshot.destination_port_first,
            snapshot.destination_port_last,
            snapshot.priority,
            snapshot.order,
            snapshot.rule_id,
            snapshot.reason_id
        );
        self.stage_intent_text(temporary, text, "stateless L4 policy intent")
    }

    fn stage_intent_text(
        &self,
        temporary: PathBuf,
        text: String,
        label: &str,
    ) -> Result<PathBuf, ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("{label} directory could not be created: {error}"),
        })?;
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("{label} temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("{label} could not be staged: {error}"),
                })?;
        }
        Ok(temporary)
    }

    pub(super) fn commit_staged_intent(
        &self,
        temporary: &Path,
        target_file: &str,
    ) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        fs::rename(temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy intent could not be published: {error}"),
        })?;
        self.remove_other_policy_intents(target_file)
    }

    fn remove_other_policy_intents(&self, target_file: &str) -> Result<(), ProductError> {
        if target_file != EMPTY_POLICY_STORE_FILE {
            self.remove_empty_intent()?;
        }
        if target_file != NETWORK_GATE_POLICY_STORE_FILE {
            self.remove_network_gate_intent()?;
        }
        if target_file != L4_POLICY_STORE_FILE {
            self.remove_l4_intent()?;
        }
        if target_file != POLICY_BUNDLE_STORE_FILE {
            self.remove_policy_bundle_intent()?;
        }
        Ok(())
    }

    pub(super) fn stage_policy_bundle(
        &self,
        bundle: &ProductPolicyBundle,
    ) -> Result<PathBuf, ProductError> {
        validate_policy_bundle(bundle)?;
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy bundle directory could not be created: {error}"),
        })?;
        let temporary = directory.join(POLICY_BUNDLE_STORE_TEMP_FILE);
        let text = serialize_policy_bundle(bundle);
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("policy bundle temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("policy bundle could not be staged: {error}"),
                })?;
        }
        Ok(temporary)
    }

    pub(super) fn commit_policy_bundle(&self, temporary: &Path) -> Result<(), ProductError> {
        let target = self.policy_bundle_state_file();
        fs::rename(temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy bundle could not be published: {error}"),
        })?;
        Ok(())
    }

    pub(super) fn discard_staged_policy_bundle(&self, temporary: &Path) {
        let _ = fs::remove_file(temporary);
    }

    #[allow(dead_code)]
    fn publish_policy_bundle(&self, bundle: &ProductPolicyBundle) -> Result<(), ProductError> {
        let temporary = self.stage_policy_bundle(bundle)?;
        if let Err(error) = self.commit_policy_bundle(&temporary) {
            self.discard_staged_policy_bundle(&temporary);
            return Err(error);
        }
        Ok(())
    }

    fn publish_next_empty_snapshot(&self) -> Result<EmptyPolicySnapshot, ProductError> {
        self.publish_empty_snapshot_revision(self.next_revision()?)
    }

    fn publish_empty_snapshot_revision(
        &self,
        revision: u64,
    ) -> Result<EmptyPolicySnapshot, ProductError> {
        let snapshot = EmptyPolicySnapshot::new(revision)?;
        self.write_intent(&snapshot)?;
        self.remove_network_gate_intent()?;
        self.remove_l4_intent()?;
        self.remove_policy_bundle_intent()?;
        Ok(snapshot)
    }

    fn publish_next_network_gate_snapshot(
        &self,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<NetworkGatePolicySnapshot, ProductError> {
        self.publish_network_gate_snapshot_revision(
            self.next_revision()?,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )
    }

    fn publish_network_gate_snapshot_revision(
        &self,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<NetworkGatePolicySnapshot, ProductError> {
        let snapshot = NetworkGatePolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?;
        self.write_network_gate_intent(&snapshot)?;
        self.remove_empty_intent()?;
        self.remove_l4_intent()?;
        self.remove_policy_bundle_intent()?;
        Ok(snapshot)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_next_l4_snapshot(
        &self,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<StatelessL4PolicySnapshot, ProductError> {
        self.publish_l4_snapshot_revision(
            self.next_revision()?,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source_cidr,
            destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_l4_snapshot_revision(
        &self,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<StatelessL4PolicySnapshot, ProductError> {
        let snapshot = StatelessL4PolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source_cidr,
            destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )?;
        self.write_l4_intent(&snapshot)?;
        self.remove_empty_intent()?;
        self.remove_network_gate_intent()?;
        self.remove_policy_bundle_intent()?;
        Ok(snapshot)
    }

    pub(super) fn next_revision(&self) -> Result<u64, ProductError> {
        let mut revision = 0_u64;
        if let Some(snapshot) = self.current_empty_snapshot()? {
            revision = revision.max(snapshot.revision);
        }
        if let Some(snapshot) = self.current_network_gate_snapshot()? {
            revision = revision.max(snapshot.revision);
        }
        if let Some(snapshot) = self.current_l4_snapshot()? {
            revision = revision.max(snapshot.revision);
        }
        if let Some(bundle) = self.current_policy_bundle()? {
            revision = revision.max(bundle.requested_revision);
        }
        revision
            .checked_add(1)
            .ok_or_else(|| ProductError::PolicyStore {
                detail: "policy revision overflow".to_owned(),
            })
    }

    fn write_intent(&self, snapshot: &EmptyPolicySnapshot) -> Result<(), ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("empty policy intent directory could not be created: {error}"),
        })?;
        let temporary = directory.join(EMPTY_POLICY_STORE_TEMP_FILE);
        let target = directory.join(EMPTY_POLICY_STORE_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=true\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=0\n",
            EMPTY_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash
        );
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("empty policy intent temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("empty policy intent could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("empty policy intent could not be published: {error}"),
        })
    }

    fn write_network_gate_intent(
        &self,
        snapshot: &NetworkGatePolicySnapshot,
    ) -> Result<(), ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("network gate policy intent directory could not be created: {error}"),
        })?;
        let temporary = directory.join(NETWORK_GATE_POLICY_STORE_TEMP_FILE);
        let target = directory.join(NETWORK_GATE_POLICY_STORE_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount={}\nl4RuleCount=0\nsubjectUid={}\nnetworkContext={}\nblocked={}\nruleId={}\nreasonId={}\n",
            NETWORK_GATE_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            if snapshot.blocked { 1 } else { 0 },
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.blocked,
            snapshot.rule_id,
            snapshot.reason_id
        );
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!(
                    "network gate policy intent temp file could not be opened: {error}"
                ),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("network gate policy intent could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("network gate policy intent could not be published: {error}"),
        })
    }

    fn write_l4_intent(&self, snapshot: &StatelessL4PolicySnapshot) -> Result<(), ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("stateless L4 policy intent directory could not be created: {error}"),
        })?;
        let temporary = directory.join(L4_POLICY_STORE_TEMP_FILE);
        let target = directory.join(L4_POLICY_STORE_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=1\nsubjectUid={}\nnetworkContext={}\nipFamily={}\nipProtocol={}\ndirection={}\naction={}\nsourceCidr={}\ndestinationCidr={}\nsourcePrefixLen={}\ndestinationPrefixLen={}\nsourcePortFirst={}\nsourcePortLast={}\ndestinationPortFirst={}\ndestinationPortLast={}\npriority={}\norder={}\nruleId={}\nreasonId={}\n",
            L4_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.ip_family,
            snapshot.ip_protocol,
            snapshot.direction,
            snapshot.action,
            snapshot.source.text,
            snapshot.destination.text,
            snapshot.source.prefix_len,
            snapshot.destination.prefix_len,
            snapshot.source_port_first,
            snapshot.source_port_last,
            snapshot.destination_port_first,
            snapshot.destination_port_last,
            snapshot.priority,
            snapshot.order,
            snapshot.rule_id,
            snapshot.reason_id
        );
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!(
                    "stateless L4 policy intent temp file could not be opened: {error}"
                ),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("stateless L4 policy intent could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("stateless L4 policy intent could not be published: {error}"),
        })
    }

    fn remove_network_gate_intent(&self) -> Result<(), ProductError> {
        let path = self.network_gate_state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale network gate policy intent could not be removed: {error}"),
            }),
        }
    }

    fn remove_empty_intent(&self) -> Result<(), ProductError> {
        let path = self.state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale empty policy intent could not be removed: {error}"),
            }),
        }
    }

    fn remove_l4_intent(&self) -> Result<(), ProductError> {
        let path = self.l4_state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale stateless L4 policy intent could not be removed: {error}"),
            }),
        }
    }

    fn remove_policy_bundle_intent(&self) -> Result<(), ProductError> {
        let path = self.policy_bundle_state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale policy bundle could not be removed: {error}"),
            }),
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.files_dir.join(EMPTY_POLICY_STORE_DIR)
    }

    fn state_file(&self) -> PathBuf {
        self.state_dir().join(EMPTY_POLICY_STORE_FILE)
    }

    fn network_gate_state_file(&self) -> PathBuf {
        self.state_dir().join(NETWORK_GATE_POLICY_STORE_FILE)
    }

    fn l4_state_file(&self) -> PathBuf {
        self.state_dir().join(L4_POLICY_STORE_FILE)
    }

    fn policy_bundle_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_BUNDLE_STORE_FILE)
    }

    fn mutation_fence_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_MUTATION_FENCE_FILE)
    }

    fn mutation_fence_temp_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_MUTATION_FENCE_TEMP_FILE)
    }

    fn mutation_candidate_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_MUTATION_CANDIDATE_FILE)
    }
}

fn parse_ipv4_cidr(value: &str, label: &str) -> Result<Ipv4Cidr, ProductError> {
    let trimmed = value.trim();
    let normalized = if trimmed.is_empty() {
        "0.0.0.0/0"
    } else {
        trimmed
    };
    let (address_text, prefix_text) =
        normalized
            .split_once('/')
            .ok_or_else(|| ProductError::PolicyStore {
                detail: format!("{label} must use IPv4 CIDR notation"),
            })?;
    let address = address_text
        .parse::<Ipv4Addr>()
        .map_err(|_| ProductError::PolicyStore {
            detail: format!("{label} address is invalid"),
        })?;
    let prefix_len = prefix_text
        .parse::<u32>()
        .ok()
        .filter(|value| *value <= 32)
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} prefix length is invalid"),
        })?;
    let mut bytes = [0_u8; 16];
    bytes[12..16].copy_from_slice(&address.octets());
    Ok(Ipv4Cidr {
        text: format!("{address}/{prefix_len}"),
        address: bytes,
        prefix_len,
    })
}

fn property_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name == key {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn required_string_property(text: &str, key: &str, label: &str) -> Result<String, ProductError> {
    property_value(text, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn fixed_text_property(text: &str, key: &str, label: &str) -> Result<[u8; 96], ProductError> {
    let value = required_string_property(text, key, label)?;
    if value.contains(['\n', '\r', '=']) || value.len() >= 96 {
        return Err(ProductError::PolicyStore {
            detail: format!("{label} {key} exceeds its fixed text field"),
        });
    }
    let mut output = [0_u8; 96];
    copy_status_text(&mut output, &value);
    Ok(output)
}

fn parse_hex_address(value: &str, label: &str) -> Result<[u8; 16], ProductError> {
    if value.len() != 32 {
        return Err(ProductError::PolicyStore {
            detail: format!("{label} must contain exactly 16 encoded bytes"),
        });
    }
    let bytes = value.as_bytes();
    let mut output = [0_u8; 16];
    for index in 0..16 {
        let text = std::str::from_utf8(&bytes[index * 2..index * 2 + 2]).map_err(|_| {
            ProductError::PolicyStore {
                detail: format!("{label} is not hexadecimal"),
            }
        })?;
        output[index] = u8::from_str_radix(text, 16).map_err(|_| ProductError::PolicyStore {
            detail: format!("{label} is not hexadecimal"),
        })?;
    }
    Ok(output)
}

fn hex_address(value: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in value {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn parse_policy_rule_entry(
    text: &str,
    family: &str,
    index: usize,
    expected_kind: u32,
) -> Result<ProductPolicyRuleEntry, ProductError> {
    let prefix = format!("{family}.{index}");
    let label = format!("policy bundle {family} entry {index}");
    let mut entry = ProductPolicyRuleEntry::zeroed();
    entry.subject_uid = required_u32_property(text, &format!("{prefix}.subjectUid"), &label)?;
    entry.network_context =
        required_u32_property(text, &format!("{prefix}.networkContext"), &label)?;
    entry.ifindex = required_u32_property(text, &format!("{prefix}.ifindex"), &label)?;
    entry.rule_kind = required_u32_property(text, &format!("{prefix}.ruleKind"), &label)?;
    entry.ip_family = required_u32_property(text, &format!("{prefix}.ipFamily"), &label)?;
    entry.ip_protocol = required_u32_property(text, &format!("{prefix}.ipProtocol"), &label)?;
    entry.direction = required_u32_property(text, &format!("{prefix}.direction"), &label)?;
    entry.action = required_u32_property(text, &format!("{prefix}.action"), &label)?;
    entry.enabled = required_u32_property(text, &format!("{prefix}.enabled"), &label)?;
    entry.source_prefix_len =
        required_u32_property(text, &format!("{prefix}.sourcePrefixLen"), &label)?;
    entry.destination_prefix_len =
        required_u32_property(text, &format!("{prefix}.destinationPrefixLen"), &label)?;
    entry.source_port_first =
        required_u32_property(text, &format!("{prefix}.sourcePortFirst"), &label)?;
    entry.source_port_last =
        required_u32_property(text, &format!("{prefix}.sourcePortLast"), &label)?;
    entry.destination_port_first =
        required_u32_property(text, &format!("{prefix}.destinationPortFirst"), &label)?;
    entry.destination_port_last =
        required_u32_property(text, &format!("{prefix}.destinationPortLast"), &label)?;
    entry.priority = required_u32_property(text, &format!("{prefix}.priority"), &label)?;
    entry.order = required_u32_property(text, &format!("{prefix}.order"), &label)?;
    entry.reason_id = required_u32_property(text, &format!("{prefix}.reasonId"), &label)?;
    entry.reserved = required_u32_property(text, &format!("{prefix}.reserved"), &label)?;
    entry.rule_id = required_u64_property(text, &format!("{prefix}.ruleId"), &label)?;
    entry.source_address = parse_hex_address(
        &required_string_property(text, &format!("{prefix}.sourceAddress"), &label)?,
        &format!("{label} sourceAddress"),
    )?;
    entry.destination_address = parse_hex_address(
        &required_string_property(text, &format!("{prefix}.destinationAddress"), &label)?,
        &format!("{label} destinationAddress"),
    )?;
    validate_policy_rule_entry(&entry, expected_kind, &label)?;
    Ok(entry)
}

fn serialize_policy_rule_entry(
    text: &mut String,
    family: &str,
    index: usize,
    entry: &ProductPolicyRuleEntry,
) {
    let prefix = format!("{family}.{index}");
    text.push_str(&format!(
        "{prefix}.subjectUid={}\n{prefix}.networkContext={}\n{prefix}.ifindex={}\n{prefix}.ruleKind={}\n{prefix}.ipFamily={}\n{prefix}.ipProtocol={}\n{prefix}.direction={}\n{prefix}.action={}\n{prefix}.enabled={}\n{prefix}.sourcePrefixLen={}\n{prefix}.destinationPrefixLen={}\n{prefix}.sourcePortFirst={}\n{prefix}.sourcePortLast={}\n{prefix}.destinationPortFirst={}\n{prefix}.destinationPortLast={}\n{prefix}.priority={}\n{prefix}.order={}\n{prefix}.reasonId={}\n{prefix}.reserved={}\n{prefix}.ruleId={}\n{prefix}.sourceAddress={}\n{prefix}.destinationAddress={}\n",
        entry.subject_uid,
        entry.network_context,
        entry.ifindex,
        entry.rule_kind,
        entry.ip_family,
        entry.ip_protocol,
        entry.direction,
        entry.action,
        entry.enabled,
        entry.source_prefix_len,
        entry.destination_prefix_len,
        entry.source_port_first,
        entry.source_port_last,
        entry.destination_port_first,
        entry.destination_port_last,
        entry.priority,
        entry.order,
        entry.reason_id,
        entry.reserved,
        entry.rule_id,
        hex_address(&entry.source_address),
        hex_address(&entry.destination_address),
    ));
}

fn serialize_policy_bundle(bundle: &ProductPolicyBundle) -> String {
    let mut text = String::with_capacity(18_000);
    text.push_str(&format!(
        "schema={POLICY_BUNDLE_STORE_SCHEMA}\nabiVersion={}\nstructSize={}\nrevision={}\nsnapshotHash={}\ngateEntryCount={}\nl4RuleCount={}\ndefaultPass={}\nsnapshotIdentity={}\n",
        bundle.abi_version,
        bundle.struct_size,
        bundle.requested_revision,
        bundle.snapshot_hash,
        bundle.gate_entry_count,
        bundle.l4_rule_count,
        bundle.default_pass,
        bounded_string(&bundle.snapshot_identity),
    ));
    for index in 0..bundle.gate_entry_count as usize {
        serialize_policy_rule_entry(&mut text, "gate", index, &bundle.gate_entries[index]);
    }
    for index in 0..bundle.l4_rule_count as usize {
        serialize_policy_rule_entry(&mut text, "l4", index, &bundle.l4_entries[index]);
    }
    text
}

fn required_u64_property(text: &str, key: &str, label: &str) -> Result<u64, ProductError> {
    property_value(text, key)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn optional_u64_property(text: &str, key: &str, label: &str) -> Result<u64, ProductError> {
    property_value(text, key)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn required_u32_property(text: &str, key: &str, label: &str) -> Result<u32, ProductError> {
    property_value(text, key)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn required_bool_property(text: &str, key: &str, label: &str) -> Result<bool, ProductError> {
    match property_value(text, key).as_deref() {
        Some("true") | Some("1") => Ok(true),
        Some("false") | Some("0") => Ok(false),
        _ => Err(ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        }),
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

pub(super) fn active_policy_matches_fence(
    status: &Status,
    fence: &PolicyMutationFence,
    expected_generation: u64,
) -> bool {
    expected_generation != 0
        && status.code == ErrorCode::Ok
        && status.generation == expected_generation
        && status.policy_requested_revision == fence.requested_revision
        && status.policy_active_revision == fence.requested_revision
        && status.policy_generation == expected_generation
        && status.policy_generation_match
        && status.policy_last_apply_status_code == 0
        && !status.policy_mixed_revision
        && status.policy_artifact_match
        && status.policy_snapshot_hash == fence.snapshot_hash
        && status.policy_snapshot_identity == fence.snapshot_identity
        && status.artifact_id == fence.artifact_id
        && status.api_identity == fence.api_identity
}

pub(super) fn is_policy_outcome_unknown(error: &ProductError) -> bool {
    matches!(
        error,
        ProductError::Native {
            code: ErrorCode::PolicyOutcomeUnknown,
            ..
        }
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn complete_fence_readback(fence: &PolicyMutationFence, generation: u64) -> Status {
        let mut status = Status::empty(generation);
        status.code = ErrorCode::Ok;
        status.policy_requested_revision = fence.requested_revision;
        status.policy_active_revision = fence.requested_revision;
        status.policy_generation = generation;
        status.policy_snapshot_hash = fence.snapshot_hash;
        status.policy_last_apply_status_code = 0;
        status.policy_artifact_match = true;
        status.policy_generation_match = true;
        status.policy_snapshot_identity = fence.snapshot_identity.clone();
        status.artifact_id = fence.artifact_id.clone();
        status.api_identity = fence.api_identity.clone();
        status
    }

    #[test]
    fn policy_bundle_validation_accepts_bounded_dual_stack_tcp_udp_entries() {
        let mut bundle = valid_policy_bundle();
        bundle.gate_entry_count = POLICY_BUNDLE_MAX_GATE_ENTRIES as u32;
        bundle.l4_rule_count = POLICY_BUNDLE_MAX_L4_ENTRIES as u32;
        for index in 0..POLICY_BUNDLE_MAX_GATE_ENTRIES {
            bundle.gate_entries[index] = valid_gate_entry(index as u64 + 1);
        }
        for index in 0..POLICY_BUNDLE_MAX_L4_ENTRIES {
            let mut entry = valid_l4_entry(index as u64 + 1000);
            if index % 2 == 1 {
                entry.ip_family = PRODUCT_POLICY_IP_FAMILY_IPV6;
                entry.ip_protocol = PRODUCT_POLICY_IP_PROTOCOL_UDP;
                entry.source_prefix_len = 128;
                entry.destination_prefix_len = 128;
            }
            bundle.l4_entries[index] = entry;
        }
        assert_eq!(validate_policy_bundle(&bundle).unwrap(), "bundle/v1");
    }

    #[test]
    fn policy_bundle_validation_rejects_capacity_and_typed_field_overflow() {
        let mut bundle = valid_policy_bundle();
        bundle.gate_entry_count = (POLICY_BUNDLE_MAX_GATE_ENTRIES as u32) + 1;
        assert!(validate_policy_bundle(&bundle).is_err());

        let mut invalid_family = valid_policy_bundle();
        invalid_family.l4_entries[0].ip_family = 5;
        assert!(validate_policy_bundle(&invalid_family).is_err());

        let mut invalid_protocol = valid_policy_bundle();
        invalid_protocol.l4_entries[0].ip_protocol = 1;
        assert!(validate_policy_bundle(&invalid_protocol).is_err());

        let mut invalid_ipv4_address = valid_policy_bundle();
        invalid_ipv4_address.l4_entries[0].source_address[15] = 1;
        assert!(validate_policy_bundle(&invalid_ipv4_address).is_err());

        let mut invalid_id = valid_policy_bundle();
        invalid_id.l4_entries[0].rule_id = 0;
        assert!(validate_policy_bundle(&invalid_id).is_err());

        let mut duplicate_id = valid_policy_bundle();
        duplicate_id.l4_entries[0].rule_id = duplicate_id.gate_entries[0].rule_id;
        assert!(validate_policy_bundle(&duplicate_id).is_err());

        let mut invalid_unused = valid_policy_bundle();
        invalid_unused.l4_entries[1].reason_id = 99;
        assert!(validate_policy_bundle(&invalid_unused).is_err());
    }

    #[test]
    fn policy_bundle_store_round_trips_one_authoritative_snapshot() {
        let root = unique_policy_dir("policy-bundle-store");
        let store = ProductPolicyStore::new(&root);
        let bundle = valid_policy_bundle();
        store.publish_policy_bundle(&bundle).unwrap();
        assert!(store.policy_bundle_state_file().is_file());
        assert!(!store.state_file().exists());
        assert_eq!(store.current_policy_bundle().unwrap(), Some(bundle));
        assert_eq!(
            store.current_snapshot().unwrap(),
            Some(RuntimePolicySnapshot::Bundle(bundle))
        );

        let mut invalid = bundle;
        invalid.l4_rule_count = (POLICY_BUNDLE_MAX_L4_ENTRIES as u32) + 1;
        assert!(store.publish_policy_bundle(&invalid).is_err());
        assert_eq!(store.current_policy_bundle().unwrap(), Some(bundle));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_policy_mutation_mismatch_discards_candidate_without_replay() {
        let root = unique_policy_dir("policy-mutation-mismatch");
        let store = ProductPolicyStore::new(&root);
        let bundle = valid_policy_bundle();
        let mut predecessor = Status::empty(9);
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();
        let fence = PolicyMutationFence::for_bundle(9, &predecessor, &bundle).unwrap();
        let temporary = store.stage_policy_bundle(&bundle).unwrap();
        store.quarantine_policy_bundle(&temporary).unwrap();
        store.write_mutation_fence(&fence).unwrap();

        let mut readback = complete_fence_readback(&fence, 10);
        readback.policy_requested_revision = predecessor.policy_active_revision;
        readback.policy_active_revision = predecessor.policy_active_revision;
        readback.policy_snapshot_hash = predecessor.policy_snapshot_hash;
        readback.policy_snapshot_identity = predecessor.policy_snapshot_identity.clone();
        assert!(!active_policy_matches_fence(&readback, &fence, 10));
        store.discard_mutation_candidate();
        store.clear_mutation_fence().unwrap();

        assert!(!store.mutation_candidate_state_file().exists());
        assert!(!store.mutation_fence_state_file().exists());
        assert!(!store.policy_bundle_state_file().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_policy_mutation_requires_complete_fresh_status() {
        let mut predecessor = Status::empty(15);
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();
        let fence =
            PolicyMutationFence::for_bundle(15, &predecessor, &valid_policy_bundle()).unwrap();
        let complete = complete_fence_readback(&fence, 16);
        assert!(active_policy_matches_fence(&complete, &fence, 16));

        let mut wrong_generation = complete.clone();
        wrong_generation.generation = 15;
        assert!(!active_policy_matches_fence(&wrong_generation, &fence, 16));

        let mut wrong_policy_generation = complete.clone();
        wrong_policy_generation.policy_generation = 15;
        assert!(!active_policy_matches_fence(
            &wrong_policy_generation,
            &fence,
            16
        ));

        let mut generation_unfenced = complete.clone();
        generation_unfenced.policy_generation_match = false;
        assert!(!active_policy_matches_fence(
            &generation_unfenced,
            &fence,
            16
        ));

        let mut apply_failed = complete.clone();
        apply_failed.policy_last_apply_status_code = 22;
        assert!(!active_policy_matches_fence(&apply_failed, &fence, 16));

        let mut artifact_unmatched = complete.clone();
        artifact_unmatched.policy_artifact_match = false;
        assert!(!active_policy_matches_fence(
            &artifact_unmatched,
            &fence,
            16
        ));

        let mut wrong_artifact = complete.clone();
        wrong_artifact.artifact_id = "different-artifact".to_owned();
        assert!(!active_policy_matches_fence(&wrong_artifact, &fence, 16));

        let mut wrong_api = complete.clone();
        wrong_api.api_identity = "different-api".to_owned();
        assert!(!active_policy_matches_fence(&wrong_api, &fence, 16));

        let mut failed_status = complete;
        failed_status.code = ErrorCode::PolicyApplyFailed;
        assert!(!active_policy_matches_fence(&failed_status, &fence, 16));
    }

    #[test]
    fn scalar_policy_stage_preserves_previous_intent_while_fenced() {
        let root = unique_policy_dir("policy-scalar-fence");
        let store = ProductPolicyStore::new(&root);
        let previous = store.publish_next_empty_snapshot().unwrap();
        let successor = EmptyPolicySnapshot::new(2).unwrap();
        let temporary = store.stage_empty_snapshot(&successor).unwrap();
        assert_eq!(store.current_empty_snapshot().unwrap().unwrap(), previous);

        let mut predecessor = Status::empty(11);
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();
        let fence = PolicyMutationFence::for_snapshot(
            11,
            &predecessor,
            &successor.to_ffi(),
            EMPTY_POLICY_STORE_FILE,
        )
        .unwrap();
        store.quarantine_policy_bundle(&temporary).unwrap();
        store.write_mutation_fence(&fence).unwrap();
        assert_eq!(store.current_empty_snapshot().unwrap().unwrap(), previous);

        store.discard_mutation_candidate();
        store.clear_mutation_fence().unwrap();
        assert_eq!(store.current_empty_snapshot().unwrap().unwrap(), previous);
        fs::remove_dir_all(root).unwrap();
    }

    pub(crate) fn valid_policy_bundle() -> ProductPolicyBundle {
        let mut bundle = ProductPolicyBundle::zeroed();
        bundle.abi_version = POLICY_BUNDLE_ABI_VERSION;
        bundle.struct_size = size_of::<ProductPolicyBundle>() as u32;
        bundle.requested_revision = 42;
        bundle.snapshot_hash = 0x0123_4567_89ab_cdef;
        bundle.gate_entry_count = 1;
        bundle.l4_rule_count = 1;
        bundle.default_pass = 1;
        copy_status_text(&mut bundle.snapshot_identity, "bundle/v1");
        bundle.gate_entries[0] = valid_gate_entry(1);
        bundle.l4_entries[0] = valid_l4_entry(2);
        bundle
    }

    fn valid_gate_entry(rule_id: u64) -> ProductPolicyRuleEntry {
        let mut entry = ProductPolicyRuleEntry::zeroed();
        entry.subject_uid = 1010001;
        entry.network_context = 1;
        entry.rule_kind = PRODUCT_POLICY_RULE_KIND_GATE;
        entry.action = PRODUCT_POLICY_ACTION_DROP;
        entry.enabled = 1;
        entry.reason_id = 136000017;
        entry.rule_id = rule_id;
        entry
    }

    fn valid_l4_entry(rule_id: u64) -> ProductPolicyRuleEntry {
        let mut entry = ProductPolicyRuleEntry::zeroed();
        entry.subject_uid = 1010001;
        entry.network_context = 1;
        entry.rule_kind = PRODUCT_POLICY_RULE_KIND_L4;
        entry.ip_family = PRODUCT_POLICY_IP_FAMILY_IPV4;
        entry.ip_protocol = PRODUCT_POLICY_IP_PROTOCOL_TCP;
        entry.direction = PRODUCT_POLICY_DIRECTION_OUTPUT;
        entry.action = PRODUCT_POLICY_ACTION_DROP;
        entry.enabled = 1;
        entry.source_prefix_len = 0;
        entry.destination_prefix_len = 32;
        entry.source_port_first = 0;
        entry.source_port_last = u16::MAX as u32;
        entry.destination_port_first = 443;
        entry.destination_port_last = 443;
        entry.priority = 10;
        entry.order = 0;
        entry.reason_id = 136000191;
        entry.rule_id = rule_id;
        entry.destination_address[0..4].copy_from_slice(&[192, 0, 2, 1]);
        entry
    }

    #[test]
    fn empty_policy_store_publishes_immutable_snapshots_with_fresh_revisions() {
        let root = unique_policy_dir("empty-policy-store");
        let store = ProductPolicyStore::new(&root);
        let first = store.publish_next_empty_snapshot().unwrap();
        let second = store.publish_next_empty_snapshot().unwrap();

        assert_eq!(first.revision, 1);
        assert_eq!(second.revision, 2);
        assert_ne!(first.snapshot_hash, second.snapshot_hash);
        assert_eq!(second.snapshot_identity, "empty-policy/v1/revision-2");
        let restored = store.current_empty_snapshot().unwrap().unwrap();
        assert_eq!(restored, second);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_policy_snapshot_ffi_has_no_gate_or_l4_claims() {
        let snapshot = EmptyPolicySnapshot::new(7).unwrap().to_ffi();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.requested_revision, 7);
        assert!(snapshot.snapshot_hash != 0);
        assert_eq!(snapshot.snapshot_empty, 1);
        assert_eq!(snapshot.default_pass, 1);
        assert_eq!(snapshot.gate_claim_count, 0);
        assert_eq!(snapshot.l4_rule_count, 0);
        assert_eq!(
            bounded_string(&snapshot.snapshot_identity),
            "empty-policy/v1/revision-7"
        );
    }

    #[test]
    fn network_gate_policy_snapshot_ffi_carries_one_gate_claim_when_blocked() {
        let snapshot =
            NetworkGatePolicySnapshot::new(8, 1010001, 1, true, 0x5100_0000_0f68_3111, 136000017)
                .unwrap()
                .to_ffi();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.requested_revision, 8);
        assert!(snapshot.snapshot_hash != 0);
        assert_eq!(snapshot.snapshot_empty, 0);
        assert_eq!(snapshot.default_pass, 1);
        assert_eq!(snapshot.gate_claim_count, 1);
        assert_eq!(snapshot.l4_rule_count, 0);
        assert_eq!(snapshot.gate_subject_uid, 1010001);
        assert_eq!(snapshot.gate_network_context, 1);
        assert_eq!(snapshot.gate_blocked, 1);
        assert_eq!(snapshot.gate_reason_id, 136000017);
        assert_eq!(snapshot.gate_rule_id, 0x5100_0000_0f68_3111);
        assert_eq!(
            bounded_string(&snapshot.snapshot_identity),
            "network-gate/v1/revision-8/uid-1010001/context-1/blocked"
        );
    }

    #[test]
    fn stateless_l4_policy_snapshot_ffi_carries_one_root_tcp_rule() {
        let snapshot = StatelessL4PolicySnapshot::new(
            9,
            1010001,
            1,
            PRODUCT_L4_IP_FAMILY_IPV4,
            PRODUCT_L4_IP_PROTOCOL_TCP,
            PRODUCT_L4_DIRECTION_OUTPUT,
            PRODUCT_L4_ACTION_DROP,
            "0.0.0.0/0",
            "192.168.4.5/32",
            0,
            65_535,
            19_191,
            19_191,
            10,
            0,
            0x5100_0000_0f68_3191,
            136000191,
        )
        .unwrap()
        .to_ffi();

        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.requested_revision, 9);
        assert!(snapshot.snapshot_hash != 0);
        assert_eq!(snapshot.snapshot_empty, 0);
        assert_eq!(snapshot.default_pass, 1);
        assert_eq!(snapshot.gate_claim_count, 0);
        assert_eq!(snapshot.l4_rule_count, 1);
        assert_eq!(snapshot.l4_subject_uid, 1010001);
        assert_eq!(snapshot.l4_network_context, 1);
        assert_eq!(snapshot.l4_ip_family, PRODUCT_L4_IP_FAMILY_IPV4);
        assert_eq!(snapshot.l4_ip_protocol, PRODUCT_L4_IP_PROTOCOL_TCP);
        assert_eq!(snapshot.l4_direction, PRODUCT_L4_DIRECTION_OUTPUT);
        assert_eq!(snapshot.l4_action, PRODUCT_L4_ACTION_DROP);
        assert_eq!(snapshot.l4_source_prefix_len, 0);
        assert_eq!(snapshot.l4_destination_prefix_len, 32);
        assert_eq!(snapshot.l4_source_port_first, 0);
        assert_eq!(snapshot.l4_source_port_last, 65_535);
        assert_eq!(snapshot.l4_destination_port_first, 19_191);
        assert_eq!(snapshot.l4_destination_port_last, 19_191);
        assert_eq!(snapshot.l4_priority, 10);
        assert_eq!(snapshot.l4_order, 0);
        assert_eq!(snapshot.l4_reason_id, 136000191);
        assert_eq!(snapshot.l4_rule_id, 0x5100_0000_0f68_3191);
        assert_eq!(&snapshot.l4_source_address[12..16], &[0, 0, 0, 0]);
        assert_eq!(&snapshot.l4_destination_address[12..16], &[192, 168, 4, 5]);
        assert_eq!(
            bounded_string(&snapshot.snapshot_identity),
            "l4tcp4/1/revision-9/uid-1010001/context-1/rule-5836665117330649489/drop"
        );
    }

    #[test]
    fn policy_store_reconciles_l4_intent_and_clears_other_policy_intents() {
        let root = unique_policy_dir("policy-store-l4");
        let store = ProductPolicyStore::new(&root);
        let empty = store.publish_next_empty_snapshot().unwrap();
        let l4 = store
            .publish_next_l4_snapshot(
                1010001,
                1,
                PRODUCT_L4_IP_FAMILY_IPV4,
                PRODUCT_L4_IP_PROTOCOL_TCP,
                PRODUCT_L4_DIRECTION_OUTPUT,
                PRODUCT_L4_ACTION_DROP,
                "0.0.0.0/0",
                "192.168.4.5/32",
                0,
                65_535,
                19_191,
                19_191,
                10,
                0,
                0x5100_0000_0f68_3191,
                136000191,
            )
            .unwrap();
        assert_eq!(empty.revision, 1);
        assert_eq!(l4.revision, 2);
        assert!(!store.state_file().exists());
        assert!(!store.network_gate_state_file().exists());
        assert!(store.l4_state_file().exists());

        let restored_l4 = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_l4.requested_revision, 2);
        assert_eq!(restored_l4.snapshot_empty, 0);
        assert_eq!(restored_l4.gate_claim_count, 0);
        assert_eq!(restored_l4.l4_rule_count, 1);
        assert_eq!(restored_l4.l4_destination_port_first, 19_191);
        assert_eq!(restored_l4.l4_destination_port_last, 19_191);

        let cleared = store.publish_next_empty_snapshot().unwrap();
        assert_eq!(cleared.revision, 3);
        assert!(!store.l4_state_file().exists());
        let restored_empty = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_empty.requested_revision, 3);
        assert_eq!(restored_empty.snapshot_empty, 1);
        assert_eq!(restored_empty.l4_rule_count, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_store_reconciles_the_latest_empty_or_network_gate_intent() {
        let root = unique_policy_dir("policy-store-latest");
        let store = ProductPolicyStore::new(&root);
        let empty = store.publish_next_empty_snapshot().unwrap();
        let gate = store
            .publish_next_network_gate_snapshot(1010001, 1, true, 0x5100_0000_0f68_3111, 136000017)
            .unwrap();
        assert_eq!(empty.revision, 1);
        assert_eq!(gate.revision, 2);
        let restored = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored.requested_revision, 2);
        assert_eq!(restored.gate_claim_count, 1);
        let open = store
            .publish_next_network_gate_snapshot(1010001, 1, false, 0x5100_0000_0f68_3111, 136000017)
            .unwrap();
        assert_eq!(open.revision, 3);
        let restored_open = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_open.requested_revision, 3);
        assert_eq!(restored_open.snapshot_empty, 0);
        assert_eq!(restored_open.gate_claim_count, 0);
        assert_eq!(restored_open.gate_blocked, 0);
        let cleared = store.publish_next_empty_snapshot().unwrap();
        assert_eq!(cleared.revision, 4);
        assert!(!store.network_gate_state_file().exists());
        let restored_empty = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_empty.requested_revision, 4);
        assert_eq!(restored_empty.snapshot_empty, 1);
        let authored_gate = store
            .publish_network_gate_snapshot_revision(
                99,
                1010001,
                1,
                true,
                0x5100_0000_0f68_3111,
                136000017,
            )
            .unwrap();
        assert_eq!(authored_gate.revision, 99);
        let restored_gate = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_gate.requested_revision, 99);
        assert_eq!(restored_gate.gate_claim_count, 1);
        let authored_open = store.publish_empty_snapshot_revision(100).unwrap();
        assert_eq!(authored_open.revision, 100);
        assert!(!store.network_gate_state_file().exists());
        let restored_open_empty = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_open_empty.requested_revision, 100);
        assert_eq!(restored_open_empty.snapshot_empty, 1);
        assert_eq!(restored_open_empty.gate_claim_count, 0);
        let stale_empty = store.publish_empty_snapshot_revision(200).unwrap();
        assert_eq!(stale_empty.revision, 200);
        let lower_authored_gate = store
            .publish_network_gate_snapshot_revision(
                101,
                1010001,
                1,
                true,
                0x5100_0000_0f68_3111,
                136000017,
            )
            .unwrap();
        assert_eq!(lower_authored_gate.revision, 101);
        assert!(!store.state_file().exists());
        let restored_lower_gate = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_lower_gate.requested_revision, 101);
        assert_eq!(restored_lower_gate.snapshot_empty, 0);
        assert_eq!(restored_lower_gate.gate_claim_count, 1);
        fs::remove_dir_all(root).unwrap();
    }

    pub(crate) fn unique_policy_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sakamoto-product-core-{name}-{}-{nanos}",
            std::process::id()
        ))
    }
}
