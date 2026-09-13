//! Serialized Product Core sessions and generation lifetime.

use crate::ffi::{
    sakamoto_product_session_apply_policy, sakamoto_product_session_apply_policy_bundle,
    sakamoto_product_session_connect, sakamoto_product_session_destroy,
    sakamoto_product_session_disconnect, sakamoto_product_session_query,
    sakamoto_product_session_set_policy_mutation_fault, ProductSession,
};
use crate::policy::{
    active_policy_matches_fence, is_policy_outcome_unknown, validate_policy_bundle,
    EmptyPolicySnapshot, NetworkGatePolicySnapshot, PolicyMutationFence, ProductPolicyStore,
    RuntimePolicySnapshot, StatelessL4PolicySnapshot, EMPTY_POLICY_STORE_FILE,
    L4_POLICY_STORE_FILE, NETWORK_GATE_POLICY_STORE_FILE,
};
use crate::{
    abi_version, api_version, validate_status_identity, ErrorCode, ProductBytes, ProductError,
    ProductPolicyBundle, ProductPolicySnapshot, ProductStatus, Status, ABI_VERSION, API_VERSION,
    POLICY_MUTATION_FAULT_NONE, POLICY_MUTATION_FAULT_OMIT_CALLBACK,
    POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT,
};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::marker::PhantomData;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct GenerationLedger {
    active: Option<u64>,
    pending: Option<u64>,
    retired: BTreeSet<u64>,
}

impl GenerationLedger {
    fn ensure_available(&self, generation: u64) -> Result<(), ProductError> {
        if let Some(active) = self.active {
            return Err(ProductError::GenerationActive { generation: active });
        }
        if let Some(pending) = self.pending {
            return Err(ProductError::GenerationActive {
                generation: pending,
            });
        }
        if self.retired.contains(&generation) {
            return Err(ProductError::GenerationRetired { generation });
        }
        Ok(())
    }

    fn reserve(&mut self, generation: u64) -> Result<(), ProductError> {
        self.ensure_available(generation)?;
        self.pending = Some(generation);
        Ok(())
    }

    fn commit(&mut self, generation: u64) {
        debug_assert_eq!(self.pending, Some(generation));
        self.pending = None;
        self.active = Some(generation);
    }

    fn release(&mut self, generation: u64) {
        if self.pending == Some(generation) {
            self.pending = None;
        }
    }

    fn retire(&mut self, generation: u64) {
        if self.active == Some(generation) {
            self.active = None;
        }
        self.retired.insert(generation);
    }
}

static GENERATION_LEDGER: OnceLock<Mutex<GenerationLedger>> = OnceLock::new();

fn generation_ledger() -> &'static Mutex<GenerationLedger> {
    GENERATION_LEDGER.get_or_init(|| Mutex::new(GenerationLedger::default()))
}

fn lock_generation_ledger() -> std::sync::MutexGuard<'static, GenerationLedger> {
    generation_ledger()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug)]
pub struct ProductCore {
    pub(super) session: Option<NonNull<ProductSession>>,
    pub(super) generation: u64,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ProductCore {
    fn ensure_mutation_unfenced(&self, store: &ProductPolicyStore) -> Result<(), ProductError> {
        if let Some(fence) = store.current_mutation_fence()? {
            return Err(ProductError::MutationFenceActive {
                generation: fence.generation,
                requested_revision: fence.requested_revision,
            });
        }
        if store.has_unresolved_mutation_artifact() {
            return Err(ProductError::PolicyStore {
                detail: "orphaned policy mutation artifact requires reconciliation".to_owned(),
            });
        }
        Ok(())
    }

    fn reconcile_unknown_mutation(
        &mut self,
        store: &ProductPolicyStore,
        fence: &PolicyMutationFence,
    ) -> Result<Status, ProductError> {
        /* A reply from the fenced generation cannot clear this record.  A
         * fresh handle first reads active state, then adopts or discards the
         * retained candidate without issuing another VAPI mutation. */
        if fence.generation == self.generation {
            return Err(ProductError::MutationFenceActive {
                generation: fence.generation,
                requested_revision: fence.requested_revision,
            });
        }
        let mut status = self.query()?;
        let active_matches = active_policy_matches_fence(&status, fence, self.generation);
        if active_matches {
            store.validate_mutation_candidate(fence)?;
            store.promote_mutation_candidate(&fence.target_file)?;
        } else {
            /* Do not replay a target that the fresh generation did not report
             * as active.  The previous durable intent remains untouched. */
            store.discard_mutation_candidate();
        }
        store.clear_mutation_fence()?;
        status.error_detail = if active_matches {
            format!(
                "unknown policy mutation reconciled by active revision readback ({})",
                fence.operation_id
            )
        } else {
            format!(
                "unknown policy mutation discarded after active revision readback ({})",
                fence.operation_id
            )
        };
        Ok(status)
    }

    pub fn connect(path: &Path, generation: u64) -> Result<(Self, Status), ProductError> {
        let actual_abi = abi_version();
        if actual_abi != ABI_VERSION {
            return Err(ProductError::AbiVersion {
                expected: ABI_VERSION,
                actual: actual_abi,
            });
        }
        let actual_api = api_version();
        if actual_api != API_VERSION {
            return Err(ProductError::ApiVersion {
                expected: API_VERSION,
                actual: actual_api,
            });
        }
        {
            let mut ledger = lock_generation_ledger();
            ledger.reserve(generation)?;
        }
        let path = match path.to_str() {
            Some(path) => path,
            None => {
                lock_generation_ledger().release(generation);
                return Err(ProductError::PathContainsNul);
            }
        };
        let path = match CString::new(path) {
            Ok(path) => path,
            Err(_) => {
                lock_generation_ledger().release(generation);
                return Err(ProductError::PathContainsNul);
            }
        };
        let bytes = ProductBytes {
            data: path.as_ptr().cast(),
            length: path.as_bytes().len().try_into().unwrap_or(u32::MAX),
        };
        let mut session = std::ptr::null_mut();
        let mut status = ProductStatus::zeroed();
        let code = unsafe {
            sakamoto_product_session_connect(bytes, generation, &mut session, &mut status)
        };
        let status = Status::from_ffi(status);
        if code != 0 {
            lock_generation_ledger().release(generation);
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        let session = match NonNull::new(session) {
            Some(session) => session,
            None => {
                lock_generation_ledger().release(generation);
                return Err(ProductError::Native {
                    code: ErrorCode::AllocationFailed,
                    status: status.clone(),
                });
            }
        };
        if let Err(error) = validate_status_identity(&status) {
            unsafe {
                let _ = sakamoto_product_session_disconnect(session.as_ptr());
                let _ = sakamoto_product_session_destroy(session.as_ptr());
            }
            lock_generation_ledger().release(generation);
            return Err(error);
        }
        let mut ledger = lock_generation_ledger();
        if ledger.pending != Some(generation) {
            unsafe {
                let _ = sakamoto_product_session_disconnect(session.as_ptr());
                let _ = sakamoto_product_session_destroy(session.as_ptr());
            }
            return Err(ProductError::GenerationActive { generation });
        }
        ledger.commit(generation);
        drop(ledger);
        Ok((
            Self {
                session: Some(session),
                generation,
                _not_send_or_sync: PhantomData,
            },
            status,
        ))
    }

    pub fn query(&mut self) -> Result<Status, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut raw = ProductStatus::zeroed();
        let code =
            unsafe { sakamoto_product_session_query(session.as_ptr(), self.generation, &mut raw) };
        let status = Status::from_ffi(raw);
        if code != 0 {
            if matches!(ErrorCode::from_raw(code), ErrorCode::StaleHandle) {
                self.retire_generation();
            }
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        validate_status_identity(&status)?;
        Ok(status)
    }

    /// Arm one debug-only, one-shot fault at the generated typed bundle
    /// boundary.  The VAPI session owns the arm so the same mutex serializes
    /// arming and consuming it with the actual bundle request.
    pub fn set_policy_mutation_fault(&mut self, fault_mode: u32) -> Result<(), ProductError> {
        if fault_mode != POLICY_MUTATION_FAULT_NONE
            && fault_mode != POLICY_MUTATION_FAULT_OMIT_CALLBACK
            && fault_mode != POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT
        {
            return Err(ProductError::Native {
                code: ErrorCode::InvalidArgument,
                status: Status {
                    code: ErrorCode::InvalidArgument,
                    error_detail: "unsupported debug policy mutation fault mode".to_owned(),
                    ..Status::empty(self.generation)
                },
            });
        }
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let code = unsafe {
            sakamoto_product_session_set_policy_mutation_fault(
                session.as_ptr(),
                self.generation,
                fault_mode,
            )
        };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status {
                    code: ErrorCode::from_raw(code),
                    error_detail: "debug policy mutation fault could not be armed".to_owned(),
                    ..Status::empty(self.generation)
                },
            });
        }
        Ok(())
    }

    pub fn apply_empty_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = EmptyPolicySnapshot::new(store.next_revision()?)?;
        let temporary = store.stage_empty_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            EMPTY_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    pub fn apply_empty_policy_revision(
        &mut self,
        files_dir: &Path,
        revision: u64,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = EmptyPolicySnapshot::new(revision)?;
        let temporary = store.stage_empty_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            EMPTY_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    pub fn apply_network_gate_policy(
        &mut self,
        files_dir: &Path,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = NetworkGatePolicySnapshot::new(
            store.next_revision()?,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?;
        let temporary = store.stage_network_gate_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            NETWORK_GATE_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    pub fn apply_network_gate_policy_revision(
        &mut self,
        files_dir: &Path,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = NetworkGatePolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?;
        let temporary = store.stage_network_gate_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            NETWORK_GATE_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_l4_policy(
        &mut self,
        files_dir: &Path,
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
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = StatelessL4PolicySnapshot::new(
            store.next_revision()?,
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
        let temporary = store.stage_l4_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            L4_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_l4_policy_revision(
        &mut self,
        files_dir: &Path,
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
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
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
        let temporary = store.stage_l4_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            L4_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    fn apply_staged_policy_snapshot(
        &mut self,
        store: &ProductPolicyStore,
        temporary: &Path,
        target_file: &str,
        snapshot: ProductPolicySnapshot,
        predecessor: &Status,
    ) -> Result<Status, ProductError> {
        match self.apply_policy_snapshot(snapshot) {
            Ok(status) => {
                if let Err(error) = store.commit_staged_intent(temporary, target_file) {
                    store.discard_staged_policy_bundle(temporary);
                    return Err(error);
                }
                Ok(status)
            }
            Err(error) if is_policy_outcome_unknown(&error) => {
                let fence = PolicyMutationFence::for_snapshot(
                    self.generation,
                    predecessor,
                    &snapshot,
                    target_file,
                )?;
                if let Err(store_error) = store.quarantine_policy_bundle(temporary) {
                    /* Keep the staged file when quarantine fails.  The
                     * unresolved-artifact gate prevents a later replay. */
                    return Err(store_error);
                }
                if let Err(store_error) = store.write_mutation_fence(&fence) {
                    /* Keep the candidate as an orphaned safety marker.  A
                     * failed fence write must not make a later caller replay
                     * an operation whose VPP outcome is still unknown. */
                    return Err(store_error);
                }
                Err(error)
            }
            Err(error) => {
                store.discard_staged_policy_bundle(temporary);
                Err(error)
            }
        }
    }

    /// Validate and publish one complete Gate + L4 successor.  The bundle is
    /// staged as one file, sent through one native apply call, and committed
    /// only after native success; a rejected native apply removes only the
    /// temporary file and leaves the previous bundle untouched.
    pub fn apply_policy_bundle(
        &mut self,
        files_dir: &Path,
        bundle: &ProductPolicyBundle,
    ) -> Result<Status, ProductError> {
        validate_policy_bundle(bundle)?;
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let temporary = store.stage_policy_bundle(bundle)?;
        match self.apply_policy_bundle_native(bundle) {
            Ok(status) => {
                if let Err(error) = store.commit_policy_bundle(&temporary) {
                    store.discard_staged_policy_bundle(&temporary);
                    return Err(error);
                }
                Ok(status)
            }
            Err(error) if is_policy_outcome_unknown(&error) => {
                let fence =
                    match PolicyMutationFence::for_bundle(self.generation, &predecessor, bundle) {
                        Ok(fence) => fence,
                        Err(fence_error) => {
                            store.discard_staged_policy_bundle(&temporary);
                            return Err(fence_error);
                        }
                    };
                if let Err(store_error) = store.quarantine_policy_bundle(&temporary) {
                    /* Keep the staged file when quarantine fails.  The
                     * unresolved-artifact gate prevents a later replay. */
                    return Err(store_error);
                }
                if let Err(store_error) = store.write_mutation_fence(&fence) {
                    /* Keep the candidate as an orphaned safety marker.  A
                     * failed fence write must not make a later caller replay
                     * an operation whose VPP outcome is still unknown. */
                    return Err(store_error);
                }
                Err(error)
            }
            Err(error) => {
                store.discard_staged_policy_bundle(&temporary);
                Err(error)
            }
        }
    }

    pub fn reconcile_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        if let Some(fence) = store.current_mutation_fence()? {
            return self.reconcile_unknown_mutation(&store, &fence);
        }
        if store.has_unresolved_mutation_artifact() {
            return Err(ProductError::PolicyStore {
                detail: "orphaned policy mutation artifact requires a durable fence".to_owned(),
            });
        }
        match store.current_snapshot()? {
            Some(snapshot) => self.reconcile_persisted_snapshot(&store, &snapshot),
            None => self.query(),
        }
    }

    pub fn reconcile_empty_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        self.reconcile_policy(files_dir)
    }

    fn reconcile_persisted_snapshot(
        &mut self,
        store: &ProductPolicyStore,
        snapshot: &RuntimePolicySnapshot,
    ) -> Result<Status, ProductError> {
        let predecessor = self.query()?;
        let target_file = snapshot.target_file();
        store.quarantine_persisted_intent(target_file)?;
        let result = match snapshot.bundle() {
            Some(bundle) => self.apply_policy_bundle_native(bundle),
            None => self.apply_policy_snapshot(snapshot.to_ffi()),
        };
        match result {
            Ok(status) => {
                if let Err(error) = store.promote_mutation_candidate(target_file) {
                    let _ = store.restore_mutation_candidate(target_file);
                    return Err(error);
                }
                Ok(status)
            }
            Err(error) if is_policy_outcome_unknown(&error) => {
                let fence = match snapshot.bundle() {
                    Some(bundle) => {
                        PolicyMutationFence::for_bundle(self.generation, &predecessor, bundle)
                    }
                    None => PolicyMutationFence::for_snapshot(
                        self.generation,
                        &predecessor,
                        &snapshot.to_ffi(),
                        target_file,
                    ),
                };
                let fence = match fence {
                    Ok(fence) => fence,
                    Err(fence_error) => {
                        /* The native outcome is already unknown.  Keep the
                         * candidate as a safety marker if identity
                         * construction fails, so a later reconcile cannot
                         * replay it without an explicit repair. */
                        return Err(fence_error);
                    }
                };
                if let Err(store_error) = store.write_mutation_fence(&fence) {
                    /* Keep the candidate when the durable fence cannot be
                     * written; orphan detection blocks automatic replay. */
                    return Err(store_error);
                }
                Err(error)
            }
            Err(error) => {
                if let Err(store_error) = store.restore_mutation_candidate(target_file) {
                    return Err(store_error);
                }
                Err(error)
            }
        }
    }

    fn apply_policy_snapshot(
        &mut self,
        snapshot: ProductPolicySnapshot,
    ) -> Result<Status, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut raw = ProductStatus::zeroed();
        let code = unsafe {
            sakamoto_product_session_apply_policy(
                session.as_ptr(),
                self.generation,
                &snapshot,
                &mut raw,
            )
        };
        let status = Status::from_ffi(raw);
        if code != 0 {
            if matches!(ErrorCode::from_raw(code), ErrorCode::StaleHandle) {
                self.retire_generation();
            }
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        validate_status_identity(&status)?;
        Ok(status)
    }

    fn apply_policy_bundle_native(
        &mut self,
        bundle: &ProductPolicyBundle,
    ) -> Result<Status, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut raw = ProductStatus::zeroed();
        let code = unsafe {
            sakamoto_product_session_apply_policy_bundle(
                session.as_ptr(),
                self.generation,
                bundle,
                &mut raw,
            )
        };
        let status = Status::from_ffi(raw);
        if code != 0 {
            if matches!(ErrorCode::from_raw(code), ErrorCode::StaleHandle) {
                self.retire_generation();
            }
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        validate_status_identity(&status)?;
        Ok(status)
    }

    pub fn disconnect(&mut self) -> Result<(), ProductError> {
        let Some(session) = self.session else {
            return Ok(());
        };
        let code = unsafe { sakamoto_product_session_disconnect(session.as_ptr()) };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status::empty(self.generation),
            });
        }
        self.retire_generation();
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn retire_generation(&self) {
        let mut ledger = lock_generation_ledger();
        ledger.retire(self.generation);
    }
}

impl Drop for ProductCore {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = unsafe { sakamoto_product_session_disconnect(session.as_ptr()) };
            let _ = unsafe { sakamoto_product_session_destroy(session.as_ptr()) };
            self.retire_generation();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::tests::{complete_fence_readback, unique_policy_dir, valid_policy_bundle};
    use std::fs;

    #[test]
    fn unknown_policy_mutation_persists_bounded_fence_and_candidate() {
        let root = unique_policy_dir("policy-mutation-fence");
        let store = ProductPolicyStore::new(&root);
        let bundle = valid_policy_bundle();
        let mut predecessor = Status::empty(7);
        predecessor.policy_active_revision = 41;
        predecessor.policy_snapshot_hash = 0x1111;
        predecessor.policy_snapshot_identity = "bundle/v1/revision-41".to_owned();
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();

        let fence = PolicyMutationFence::for_bundle(7, &predecessor, &bundle).unwrap();
        let temporary = store.stage_policy_bundle(&bundle).unwrap();
        store.quarantine_policy_bundle(&temporary).unwrap();
        store.write_mutation_fence(&fence).unwrap();

        assert_eq!(store.current_mutation_fence().unwrap(), Some(fence.clone()));
        assert!(root
            .join("product-policy/policy-mutation-candidate.properties")
            .is_file());
        assert!(root
            .join("product-policy/policy-mutation-fence.properties")
            .is_file());

        let mut old_generation = ProductCore {
            session: None,
            generation: 7,
            _not_send_or_sync: PhantomData,
        };
        assert!(matches!(
            old_generation.reconcile_unknown_mutation(&store, &fence),
            Err(ProductError::MutationFenceActive {
                generation: 7,
                requested_revision: 42
            })
        ));
        assert!(root
            .join("product-policy/policy-mutation-fence.properties")
            .is_file());

        let readback = complete_fence_readback(&fence, 8);
        assert!(active_policy_matches_fence(&readback, &fence, 8));
        assert!(!active_policy_matches_fence(&predecessor, &fence, 8));

        store
            .promote_mutation_candidate(&fence.target_file)
            .unwrap();
        store.clear_mutation_fence().unwrap();
        assert_eq!(
            store.current_snapshot().unwrap(),
            Some(RuntimePolicySnapshot::Bundle(bundle))
        );
        assert!(!root
            .join("product-policy/policy-mutation-fence.properties")
            .exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn product_core_requires_a_generation() {
        let error = ProductCore::connect(Path::new("/does/not/exist"), 0).unwrap_err();
        assert!(matches!(
            error,
            ProductError::Native {
                code: ErrorCode::InvalidArgument,
                ..
            }
        ));
    }

    #[test]
    fn generation_ledger_allows_only_one_active_generation() {
        let mut ledger = GenerationLedger::default();
        assert!(ledger.reserve(7).is_ok());
        ledger.commit(7);
        assert!(matches!(
            ledger.reserve(8),
            Err(ProductError::GenerationActive { generation: 7 })
        ));
        ledger.retire(7);
        assert!(matches!(
            ledger.reserve(7),
            Err(ProductError::GenerationRetired { generation: 7 })
        ));
        assert!(ledger.reserve(8).is_ok());
    }
}
