#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeSet;
use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_uint;
use std::panic::{catch_unwind, AssertUnwindSafe};
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
    DisconnectFailed,
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
            11 => Self::DisconnectFailed,
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
            Self::DisconnectFailed => 11,
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

impl ProductError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::AbiVersion { .. } | Self::ApiVersion { .. } => ErrorCode::ProtocolMismatch,
            Self::Native { code, .. } => *code,
            Self::PathContainsNul => ErrorCode::InvalidArgument,
            Self::GenerationActive { .. } | Self::GenerationRetired { .. } => {
                ErrorCode::StaleHandle
            }
        }
    }
}

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
    session: Option<NonNull<ProductSession>>,
    generation: u64,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// Opaque owner exposed by the small C facade below.
///
/// The pointer is deliberately the only thing crossing the native boundary;
/// ProductCore and its generated-VAPI session remain Rust-owned.
#[repr(C)]
pub struct ProductCoreHandle {
    core: ProductCore,
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

fn copy_status_text(destination: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    let count = bytes.len().min(destination.len().saturating_sub(1));
    if count != 0 {
        destination[..count].copy_from_slice(&bytes[..count]);
    }
    if !destination.is_empty() {
        destination[count] = 0;
    }
}

fn status_to_ffi(status: &Status) -> ProductStatus {
    let mut value = ProductStatus::zeroed();
    value.abi_version = status.abi_version;
    value.api_version = status.api_version;
    value.status_code = status.code.raw();
    value.generation = status.generation;
    value.core_ready = u32::from(status.core_ready);
    value.adapter_available = u32::from(status.adapter_available);
    value.protection_running = u32::from(status.protection_running);
    value.plugin_loaded = u32::from(status.plugin_loaded);
    value.vapi_handle_live = u32::from(status.vapi_handle_live);
    value.generation_live = u32::from(status.generation_live);
    copy_status_text(&mut value.artifact_id, &status.artifact_id);
    copy_status_text(&mut value.api_identity, &status.api_identity);
    copy_status_text(&mut value.vpp_revision, &status.vpp_revision);
    copy_status_text(&mut value.error_detail, &status.error_detail);
    value
}

fn error_status(error: &ProductError, generation: u64) -> ProductStatus {
    match error {
        ProductError::Native { status, .. } => status_to_ffi(status),
        ProductError::AbiVersion { actual, .. } => {
            let mut status = Status::empty(generation);
            status.abi_version = *actual;
            status.code = ErrorCode::ProtocolMismatch;
            status.error_detail = "Product Core ABI version mismatch".to_owned();
            status_to_ffi(&status)
        }
        ProductError::ApiVersion { actual, .. } => {
            let mut status = Status::empty(generation);
            status.api_version = *actual;
            status.code = ErrorCode::ProtocolMismatch;
            status.error_detail = "Product Core API version mismatch".to_owned();
            status_to_ffi(&status)
        }
        ProductError::PathContainsNul => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::InvalidArgument;
            status.error_detail = "API socket path is invalid".to_owned();
            status_to_ffi(&status)
        }
        ProductError::GenerationActive { generation: active } => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.generation = *active;
            status.error_detail = "another Product Core generation is active".to_owned();
            status_to_ffi(&status)
        }
        ProductError::GenerationRetired {
            generation: retired,
        } => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.generation = *retired;
            status.error_detail = "Product Core generation has been retired".to_owned();
            status_to_ffi(&status)
        }
    }
}

fn invalid_status(generation: u64, detail: &str) -> ProductStatus {
    let mut status = Status::empty(generation);
    status.code = ErrorCode::InvalidArgument;
    status.error_detail = detail.to_owned();
    status_to_ffi(&status)
}

fn panic_status(generation: u64) -> ProductStatus {
    let mut status = Status::empty(generation);
    status.code = ErrorCode::InternalError;
    status.error_detail = "Product Core facade panicked".to_owned();
    status_to_ffi(&status)
}

fn socket_path(bytes: ProductBytes) -> Result<String, ProductError> {
    if bytes.data.is_null() || bytes.length == 0 {
        return Err(ProductError::PathContainsNul);
    }
    let bytes = unsafe { std::slice::from_raw_parts(bytes.data, bytes.length as usize) };
    if bytes.contains(&0) {
        return Err(ProductError::PathContainsNul);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| ProductError::PathContainsNul)?;
    Ok(value.to_owned())
}

/// Connect a Rust-owned ProductCore and return its first status.
///
/// The function catches Rust panics so no unwinding crosses JNI/C. The caller
/// must pass valid writable output pointers and must later destroy a returned
/// handle exactly once.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_connect(
    api_socket: ProductBytes,
    generation: u64,
    out_handle: *mut *mut ProductCoreHandle,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_handle.is_null() || out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        *out_handle = std::ptr::null_mut();
        *out_status = invalid_status(generation, "invalid Product Core connect arguments");
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = match socket_path(api_socket) {
            Ok(path) => path,
            Err(error) => {
                let status = error_status(&error, generation);
                unsafe { *out_status = status };
                return Err(error);
            }
        };
        match ProductCore::connect(Path::new(&path), generation) {
            Ok((core, status)) => {
                unsafe {
                    *out_status = status_to_ffi(&status);
                    *out_handle = Box::into_raw(Box::new(ProductCoreHandle { core }));
                }
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error)
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(error)) => error_status(&error, generation).status_code,
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Query the same Rust-owned ProductCore session for a generation.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_query(
    handle: *mut ProductCoreHandle,
    generation: u64,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core query arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.query() {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Disconnect a ProductCore session while retaining its tombstone handle.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_disconnect(
    handle: *mut ProductCoreHandle,
) -> c_uint {
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = unsafe { &mut *handle };
        handle.core.disconnect().map_err(|error| error.code())
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

/// Destroy a handle after disconnecting it. Drop remains the final safety net.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_destroy(handle: *mut ProductCoreHandle) -> c_uint {
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut handle = unsafe { Box::from_raw(handle) };
        let code = handle.core.disconnect().map_err(|error| error.code());
        drop(handle);
        code
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => ErrorCode::InternalError.raw(),
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
