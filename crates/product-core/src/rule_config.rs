//! Online source configuration is owned by VPP. These are packet-free adapters.
use crate::{ffi, ErrorCode, ProductCore, ProductError, Status};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigRule {
    pub present: u32,
    pub uid: u32,
    pub protocol: u32,
    pub direction: u32,
    pub action: u32,
    pub source_port: u32,
    pub destination_port: u32,
    pub reserved: u32,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleConfigRequest {
    pub schema: u32,
    pub operation: u32,
    pub expected_saved_revision: u64,
    pub rule: ConfigRule,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RuleConfigStatus {
    pub generation: u64,
    pub saved_revision: u64,
    pub active_revision: u64,
    pub saved_rule_version: u64,
    pub active_rule_version: u64,
    pub result: u32,
    pub save_error: u32,
    pub compile_error: u32,
    pub reserved: u32,
    pub rule: ConfigRule,
}

impl ProductCore {
    pub fn rule_config(
        &mut self,
        request: &RuleConfigRequest,
    ) -> Result<RuleConfigStatus, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut status = RuleConfigStatus::default();
        let code = unsafe {
            ffi::sakamoto_product_session_rule_config(
                session.as_ptr(),
                self.generation,
                request,
                &mut status,
            )
        };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status {
                    code: ErrorCode::from_raw(code),
                    error_detail:
                        "online VPP rule configuration request failed; query before retrying".into(),
                    ..Status::empty(self.generation)
                },
            });
        }
        Ok(status)
    }

    pub fn query_rule_config(&mut self) -> Result<RuleConfigStatus, ProductError> {
        self.rule_config(&RuleConfigRequest {
            schema: 1,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_width_online_contract_retains_full_unsigned_rule_version() {
        assert_eq!(std::mem::size_of::<ConfigRule>(), 40);
        assert_eq!(std::mem::size_of::<RuleConfigRequest>(), 56);
        assert_eq!(std::mem::size_of::<RuleConfigStatus>(), 96);
        let status = RuleConfigStatus {
            saved_rule_version: 0xfedc_ba98_7654_0001,
            ..Default::default()
        };
        assert_eq!(status.saved_rule_version >> 16, 0xfedc_ba98_7654);
        assert_eq!(status.saved_rule_version & 65535, 1);
    }
}
