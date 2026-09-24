use sakamoto_product_core::{
    ConfigRule, ErrorCode, ProductCore, ProductError, RuleConfigRequest, Status,
};
use std::env;
use std::path::Path;

fn print_status(label: &str, status: &Status) {
    println!("{label}.code={:?}", status.code);
    println!("{label}.code_value={}", status.code.raw());
    println!("{label}.abi_version={}", status.abi_version);
    println!("{label}.api_version={}", status.api_version);
    println!("{label}.generation={}", status.generation);
    println!("{label}.core_ready={}", status.core_ready);
    println!("{label}.adapter_available={}", status.adapter_available);
    println!("{label}.protection_running={}", status.protection_running);
    println!("{label}.plugin_loaded={}", status.plugin_loaded);
    println!("{label}.vapi_handle_live={}", status.vapi_handle_live);
    println!("{label}.generation_live={}", status.generation_live);
    println!("{label}.artifact_id={}", status.artifact_id);
    println!("{label}.api_identity={}", status.api_identity);
    println!("{label}.vpp_revision={}", status.vpp_revision);
    println!(
        "{label}.policy_requested_revision={}",
        status.policy_requested_revision
    );
    println!(
        "{label}.policy_active_revision={}",
        status.policy_active_revision
    );
    println!("{label}.policy_generation={}", status.policy_generation);
    println!(
        "{label}.policy_snapshot_identity={}",
        status.policy_snapshot_identity
    );
    println!("{label}.error_detail={}", status.error_detail);
    println!(
        "{label}.winner_version={}",
        status.policy_l4_last_match_rule_id
    );
    println!(
        "{label}.winner_revision={}",
        status.policy_l4_last_match_revision
    );
    println!(
        "{label}.winner_action={}",
        status.policy_l4_last_match_action
    );
    println!(
        "{label}.evaluation={}",
        status.policy_l4_last_evaluation_result
    );
    println!(
        "{label}.verdict={}",
        status.policy_l4_last_evaluation_verdict
    );
}

fn usage() -> ! {
    eprintln!("usage: sakamoto-product-core-host <query|rule-query|rule-clear> <api-socket> <generation> [expected-saved]\n       sakamoto-product-core-host rule-replace <api-socket> <generation> <expected-saved> <uid> <src-ipv4> <dst-ipv4> <src-port> <dst-port> <allow|drop>");
    std::process::exit(2);
}

fn main() {
    let mut arguments = env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| usage());
    let Some(socket) = arguments.next() else {
        usage()
    };
    let Some(generation) = arguments.next() else {
        usage()
    };
    let remaining: Vec<String> = arguments.collect();
    let generation: u64 = generation.parse().unwrap_or_else(|_| usage());
    let (mut core, connected) = match ProductCore::connect(Path::new(&socket), generation) {
        Ok(value) => value,
        Err(error) => {
            print_error(error);
            std::process::exit(1);
        }
    };
    print_status("connect", &connected);
    if command.starts_with("rule-") {
        let mut request = RuleConfigRequest {
            schema: 1,
            ..Default::default()
        };
        let number = |index: usize| -> u64 {
            remaining
                .get(index)
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| usage())
        };
        match command.as_str() {
            "rule-query" if remaining.is_empty() => {}
            "rule-clear" if remaining.len() == 1 => {
                request.operation = 1;
                request.expected_saved_revision = number(0);
            }
            "rule-replace" if remaining.len() == 7 => {
                request.operation = 1;
                request.expected_saved_revision = number(0);
                request.rule = ConfigRule {
                    present: 1,
                    uid: u32::try_from(number(1)).unwrap_or_else(|_| usage()),
                    protocol: 17,
                    direction: 3,
                    action: match remaining[6].as_str() {
                        "allow" => 1,
                        "drop" => 2,
                        _ => usage(),
                    },
                    source_port: u32::try_from(number(4)).unwrap_or_else(|_| usage()),
                    destination_port: u32::try_from(number(5)).unwrap_or_else(|_| usage()),
                    source_address: remaining[2]
                        .parse::<std::net::Ipv4Addr>()
                        .unwrap_or_else(|_| usage())
                        .octets(),
                    destination_address: remaining[3]
                        .parse::<std::net::Ipv4Addr>()
                        .unwrap_or_else(|_| usage())
                        .octets(),
                    ..Default::default()
                };
            }
            _ => usage(),
        }
        match core.rule_config(&request) {
            Ok(s) => {
                println!("config.generation={}\nconfig.saved_revision={}\nconfig.active_revision={}\nconfig.saved_rule_version={}\nconfig.active_rule_version={}\nconfig.result={}\nconfig.save_error={}\nconfig.compile_error={}\nconfig.present={}\nconfig.uid={}\nconfig.action={}",
                    s.generation, s.saved_revision, s.active_revision, s.saved_rule_version,
                    s.active_rule_version, s.result, s.save_error, s.compile_error,
                    s.rule.present, s.rule.uid, s.rule.action);
                if s.result != 0 {
                    std::process::exit(1);
                }
            }
            Err(error) => {
                print_error(error);
                std::process::exit(1);
            }
        }
    } else if command != "query" || !remaining.is_empty() {
        usage();
    }
    let queried = match core.query() {
        Ok(status) => status,
        Err(error) => {
            print_error(error);
            std::process::exit(1);
        }
    };
    print_status("query", &queried);
    if queried.code != ErrorCode::Ok || !queried.core_ready {
        eprintln!("product core management is not ready");
        std::process::exit(1);
    }
}

fn print_error(error: ProductError) {
    eprintln!("product core error: {error:?}");
}
