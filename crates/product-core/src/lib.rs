#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeSet;
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_uint;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductBytes {
    pub data: *const u8,
    pub length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductStatus {
    pub abi_version: u32,
    pub api_version: u32,
    pub status_code: u32,
    pub reserved: u32,
    pub generation: u64,
    pub core_ready: u32,
    pub adapter_available: u32,
    pub protection_running: u32,
    pub plugin_loaded: u32,
    pub vapi_handle_live: u32,
    pub generation_live: u32,
    pub reserved_flags: u32,
    pub artifact_id: [u8; 96],
    pub api_identity: [u8; 96],
    pub vpp_revision: [u8; 48],
    pub error_detail: [u8; 128],
}

#[repr(C)]
struct ProductSession {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn sakamoto_product_abi_version() -> c_uint;
    fn sakamoto_product_api_version() -> c_uint;
    fn sakamoto_product_session_connect(
        api_socket: ProductBytes,
        expected_generation: u64,
        out_session: *mut *mut ProductSession,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    fn sakamoto_product_session_query(
        session: *mut ProductSession,
        expected_generation: u64,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    fn sakamoto_product_session_disconnect(session: *mut ProductSession) -> c_uint;
    fn sakamoto_product_session_destroy(session: *mut ProductSession) -> c_uint;
}

pub const ABI_VERSION: u32 = 1;
pub const API_VERSION: u32 = 1;

pub fn abi_version() -> u32 {
    unsafe { sakamoto_product_abi_version() }
}

pub fn api_version() -> u32 {
    unsafe { sakamoto_product_api_version() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Ok,
    InvalidArgument,
    AllocationFailed,
    ConnectFailed,
    Disconnected,
    StaleHandle,
    ApiUnavailable,
    QueryFailed,
    ProtocolMismatch,
    InternalError,
    UnknownTag,
    Unknown(u32),
}

impl ErrorCode {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Ok,
            1 => Self::InvalidArgument,
            2 => Self::AllocationFailed,
            3 => Self::ConnectFailed,
            4 => Self::Disconnected,
            5 => Self::StaleHandle,
            6 => Self::ApiUnavailable,
            7 => Self::QueryFailed,
            8 => Self::ProtocolMismatch,
            9 => Self::InternalError,
            10 => Self::UnknownTag,
            value => Self::Unknown(value),
        }
    }

    pub fn raw(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::InvalidArgument => 1,
            Self::AllocationFailed => 2,
            Self::ConnectFailed => 3,
            Self::Disconnected => 4,
            Self::StaleHandle => 5,
            Self::ApiUnavailable => 6,
            Self::QueryFailed => 7,
            Self::ProtocolMismatch => 8,
            Self::InternalError => 9,
            Self::UnknownTag => 10,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub abi_version: u32,
    pub api_version: u32,
    pub code: ErrorCode,
    pub generation: u64,
    pub core_ready: bool,
    pub adapter_available: bool,
    pub protection_running: bool,
    pub plugin_loaded: bool,
    pub vapi_handle_live: bool,
    pub generation_live: bool,
    pub artifact_id: String,
    pub api_identity: String,
    pub vpp_revision: String,
    pub error_detail: String,
}

impl Status {
    fn from_ffi(value: ProductStatus) -> Self {
        Self {
            abi_version: value.abi_version,
            api_version: value.api_version,
            code: ErrorCode::from_raw(value.status_code),
            generation: value.generation,
            core_ready: value.core_ready != 0,
            adapter_available: value.adapter_available != 0,
            protection_running: value.protection_running != 0,
            plugin_loaded: value.plugin_loaded != 0,
            vapi_handle_live: value.vapi_handle_live != 0,
            generation_live: value.generation_live != 0,
            artifact_id: bounded_string(&value.artifact_id),
            api_identity: bounded_string(&value.api_identity),
            vpp_revision: bounded_string(&value.vpp_revision),
            error_detail: bounded_string(&value.error_detail),
        }
    }
}

fn validate_status_identity(status: &Status) -> Result<(), ProductError> {
    if status.abi_version != ABI_VERSION {
        return Err(ProductError::AbiVersion {
            expected: ABI_VERSION,
            actual: status.abi_version,
        });
    }
    if status.api_version != API_VERSION {
        return Err(ProductError::ApiVersion {
            expected: API_VERSION,
            actual: status.api_version,
        });
    }
    Ok(())
}

fn bounded_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProductError {
    AbiVersion { expected: u32, actual: u32 },
    ApiVersion { expected: u32, actual: u32 },
    Native { code: ErrorCode, status: Status },
    PathContainsNul,
    GenerationActive { generation: u64 },
    GenerationRetired { generation: u64 },
}

#[derive(Default)]
struct GenerationLedger {
    active: Option<u64>,
    retired: BTreeSet<u64>,
}

impl GenerationLedger {
    fn ensure_available(&self, generation: u64) -> Result<(), ProductError> {
        if let Some(active) = self.active {
            return Err(ProductError::GenerationActive { generation: active });
        }
        if self.retired.contains(&generation) {
            return Err(ProductError::GenerationRetired { generation });
        }
        Ok(())
    }

    fn claim(&mut self, generation: u64) -> Result<(), ProductError> {
        self.ensure_available(generation)?;
        self.active = Some(generation);
        Ok(())
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
    session: Option<NonNull<ProductSession>>,
    generation: u64,
    _not_send_or_sync: PhantomData<*mut ()>,
}

impl ProductCore {
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
            let ledger = lock_generation_ledger();
            ledger.ensure_available(generation)?;
        }
        let path = path.to_str().ok_or(ProductError::PathContainsNul)?;
        let path = CString::new(path).map_err(|_| ProductError::PathContainsNul)?;
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
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        let session = NonNull::new(session).ok_or(ProductError::Native {
            code: ErrorCode::AllocationFailed,
            status: status.clone(),
        })?;
        if let Err(error) = validate_status_identity(&status) {
            unsafe {
                let _ = sakamoto_product_session_disconnect(session.as_ptr());
                let _ = sakamoto_product_session_destroy(session.as_ptr());
            }
            return Err(error);
        }
        let mut ledger = lock_generation_ledger();
        if let Err(error) = ledger.claim(generation) {
            unsafe {
                let _ = sakamoto_product_session_disconnect(session.as_ptr());
                let _ = sakamoto_product_session_destroy(session.as_ptr());
            }
            return Err(error);
        }
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

impl ProductStatus {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl Status {
    fn empty(generation: u64) -> Self {
        Self {
            abi_version: ABI_VERSION,
            api_version: API_VERSION,
            code: ErrorCode::Disconnected,
            generation,
            core_ready: false,
            adapter_available: false,
            protection_running: false,
            plugin_loaded: false,
            vapi_handle_live: false,
            generation_live: false,
            artifact_id: String::new(),
            api_identity: String::new(),
            vpp_revision: String::new(),
            error_detail: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn abi_layout_is_explicit_and_stable() {
        assert_eq!(size_of::<ProductBytes>(), 16);
        assert_eq!(align_of::<ProductBytes>(), 8);
        assert_eq!(size_of::<ProductStatus>(), 424);
        assert_eq!(align_of::<ProductStatus>(), 8);
    }

    #[test]
    fn unknown_integer_tags_are_not_accepted_as_known_errors() {
        assert_eq!(
            ErrorCode::from_raw(0xfeed_beef),
            ErrorCode::Unknown(0xfeed_beef)
        );
        assert_eq!(ErrorCode::Unknown(0xfeed_beef).raw(), 0xfeed_beef);
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
        assert!(ledger.claim(7).is_ok());
        assert!(matches!(
            ledger.claim(8),
            Err(ProductError::GenerationActive { generation: 7 })
        ));
        ledger.retire(7);
        assert!(matches!(
            ledger.claim(7),
            Err(ProductError::GenerationRetired { generation: 7 })
        ));
        assert!(ledger.claim(8).is_ok());
    }

    #[test]
    fn status_identity_versions_are_checked_at_the_typed_boundary() {
        let mut status = Status::empty(9);
        status.abi_version = ABI_VERSION + 1;
        assert!(matches!(
            validate_status_identity(&status),
            Err(ProductError::AbiVersion {
                expected: ABI_VERSION,
                actual: 2
            })
        ));
        status.abi_version = ABI_VERSION;
        status.api_version = API_VERSION + 1;
        assert!(matches!(
            validate_status_identity(&status),
            Err(ProductError::ApiVersion {
                expected: API_VERSION,
                actual: 2
            })
        ));
    }
}
