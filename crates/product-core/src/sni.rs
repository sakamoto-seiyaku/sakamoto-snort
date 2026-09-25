//! Identity-fenced, read-only SNI facts owned by VPP.
use crate::{ffi, ErrorCode, ProductCore, ProductError, Status};
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SniStatus {
    pub generation: u64,
    pub incarnation: u64,
    pub protocols: u64,
    pub worker: u32,
    pub slot: u32,
    pub result: u32,
    pub stop: u32,
    pub attempts: u32,
    pub bytes: u32,
    pub work: u32,
    pub cache_bytes: u32,
    pub name_length: u32,
    pub protocols_available: u32,
    pub name: [u8; 254],
}
impl Default for SniStatus {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
impl ProductCore {
    pub fn query_sni(
        &mut self,
        worker: u32,
        slot: u32,
        incarnation: u64,
    ) -> Result<SniStatus, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut result = SniStatus::default();
        let code = unsafe {
            ffi::sakamoto_product_session_sni_query(
                session.as_ptr(),
                self.generation,
                worker,
                slot,
                incarnation,
                &mut result,
            )
        };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status::empty(self.generation),
            });
        }
        Ok(result)
    }
}
