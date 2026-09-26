//! Serialized Product Core sessions and generation lifetime.

use crate::ffi::{
    sakamoto_product_session_connect, sakamoto_product_session_destroy,
    sakamoto_product_session_disconnect, sakamoto_product_session_query,
    sakamoto_product_session_set_policy_mutation_fault, ProductSession,
};
use crate::{
    abi_version, api_version, validate_status_identity, ErrorCode, ProductBytes, ProductError,
    ProductPolicyBundle, ProductStatus, Status, ABI_VERSION, API_VERSION,
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
    pub(super) api_path: std::path::PathBuf,
    pub(super) observation: Option<crate::observation_service::ObservationService>,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ProductCore {
    pub fn connect(path: &Path, generation: u64) -> Result<(Self, Status), ProductError> {
        let api_path = path.to_path_buf();
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
                api_path,
                observation: None,
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

    fn retired_policy_writer(&self) -> Result<Status, ProductError> {
        Err(ProductError::Native {
            code: ErrorCode::ApiUnavailable,
            status: Status {
                code: ErrorCode::ApiUnavailable,
                error_detail: "legacy authoring is retired; use online VPP rule configuration"
                    .into(),
                ..Status::empty(self.generation)
            },
        })
    }

    pub fn apply_empty_policy(&mut self, _files_dir: &Path) -> Result<Status, ProductError> {
        let current = self.query_rule_config()?;
        let result = self.rule_config(&crate::RuleConfigRequest {
            schema: 1,
            operation: 1,
            expected_saved_revision: current.saved_revision,
            ..Default::default()
        })?;
        if result.result != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::PolicyApplyFailed,
                status: Status {
                    code: ErrorCode::PolicyApplyFailed,
                    error_detail: format!("VPP configuration failed: {}", result.result),
                    ..Status::empty(self.generation)
                },
            });
        }
        self.query()
    }

    pub fn apply_empty_policy_revision(
        &mut self,
        _files_dir: &Path,
        _revision: u64,
    ) -> Result<Status, ProductError> {
        self.retired_policy_writer()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_network_gate_policy(
        &mut self,
        _files_dir: &Path,
        _subject_uid: u32,
        _network_context: u32,
        _blocked: bool,
        _rule_id: u64,
        _reason_id: u32,
    ) -> Result<Status, ProductError> {
        self.retired_policy_writer()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_network_gate_policy_revision(
        &mut self,
        _files_dir: &Path,
        _revision: u64,
        _subject_uid: u32,
        _network_context: u32,
        _blocked: bool,
        _rule_id: u64,
        _reason_id: u32,
    ) -> Result<Status, ProductError> {
        self.retired_policy_writer()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_l4_policy(
        &mut self,
        _files_dir: &Path,
        _subject_uid: u32,
        _network_context: u32,
        _ip_family: u32,
        _ip_protocol: u32,
        _direction: u32,
        _action: u32,
        _source_cidr: &str,
        _destination_cidr: &str,
        _source_port_first: u32,
        _source_port_last: u32,
        _destination_port_first: u32,
        _destination_port_last: u32,
        _priority: u32,
        _order: u32,
        _rule_id: u64,
        _reason_id: u32,
    ) -> Result<Status, ProductError> {
        self.retired_policy_writer()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_l4_policy_revision(
        &mut self,
        _files_dir: &Path,
        _revision: u64,
        _subject_uid: u32,
        _network_context: u32,
        _ip_family: u32,
        _ip_protocol: u32,
        _direction: u32,
        _action: u32,
        _source_cidr: &str,
        _destination_cidr: &str,
        _source_port_first: u32,
        _source_port_last: u32,
        _destination_port_first: u32,
        _destination_port_last: u32,
        _priority: u32,
        _order: u32,
        _rule_id: u64,
        _reason_id: u32,
    ) -> Result<Status, ProductError> {
        self.retired_policy_writer()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_policy_bundle(
        &mut self,
        _files_dir: &Path,
        _bundle: &ProductPolicyBundle,
    ) -> Result<Status, ProductError> {
        self.retired_policy_writer()
    }

    pub fn reconcile_policy(&mut self, _files_dir: &Path) -> Result<Status, ProductError> {
        // VPP loads and compiles its source before Adapter admission. No replay
        // from a Rust-owned snapshot or unknown-mutation candidate is allowed.
        self.query_rule_config()?;
        self.query()
    }

    pub fn reconcile_empty_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        self.reconcile_policy(files_dir)
    }

    pub fn disconnect(&mut self) -> Result<(), ProductError> {
        self.observation.take();
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
        self.observation.take();
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

    #[test]
    fn retired_writer_does_not_create_an_offline_policy() {
        let root = std::env::temp_dir().join(format!("t01-retired-{}", std::process::id()));
        assert!(!root.exists());
        let mut core = ProductCore {
            session: None,
            generation: 7,
            api_path: std::path::PathBuf::new(),
            observation: None,
            _not_send_or_sync: PhantomData,
        };
        assert!(matches!(
            core.apply_network_gate_policy(&root, 12345, 1, true, 1, 1),
            Err(ProductError::Native {
                code: ErrorCode::ApiUnavailable,
                ..
            })
        ));
        assert!(!root.exists());
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
