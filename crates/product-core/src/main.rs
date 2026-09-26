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
    println!("{label}.logical_hits={}", status.policy_l4_match_records);
    println!("{label}.actual_drops={}", status.policy_drop_records);
    println!("{label}.effective_rules={}", status.policy_l4_rule_count);
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
    eprintln!("usage: sakamoto-product-core-host <query|rule-query|rule-clear|rule-export> <api-socket> <generation> [expected-saved]\n       sakamoto-product-core-host rule-import <api-socket> <generation> <expected-saved> <json-file>\n       sakamoto-product-core-host rule-replace <api-socket> <generation> <expected-saved> <uid> <src-ipv4> <dst-ipv4> <src-port> <dst-port> <allow|drop>");
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
    if command == "observation-query" {
        println!("observation.response={}", core.observation_json());
        return;
    }
    if command == "observation-serve" {
        use std::io::{BufRead, Write};
        if let Err(error) = core.start_observation() {
            eprintln!("observation.start={error}");
            std::process::exit(1);
        }
        println!("observation.ready={generation}");
        std::io::stdout().flush().unwrap();
        for line in std::io::stdin().lock().lines() {
            match line.unwrap_or_default().trim() {
                "pause" => {
                    core.pause_observation(true).unwrap();
                    println!("observation.paused=true");
                }
                "resume" => {
                    core.pause_observation(false).unwrap();
                    println!("observation.paused=false");
                }
                "query" => println!("observation.response={}", core.observation_json()),
                "quit" => break,
                _ => println!("observation.error=unknown_command"),
            }
            std::io::stdout().flush().unwrap();
        }
        return;
    }
    if command == "rule-import" || command == "rule-export" {
        use std::io::Read;
        let (expected_revision, text) = if command == "rule-import" && remaining.len() == 2 {
            let revision = remaining[0].parse::<u64>().unwrap_or_else(|_| usage());
            let file = std::fs::File::open(&remaining[1]).unwrap_or_else(|_| usage());
            let mut text = String::new();
            file.take(1024 * 1024 + 1)
                .read_to_string(&mut text)
                .unwrap_or_else(|_| usage());
            (revision, Some(text))
        } else if command == "rule-export" && remaining.is_empty() {
            (0, None)
        } else {
            usage()
        };
        let response = core.rule_import_json(text.as_deref(), expected_revision);
        println!("import.response={response}");
        let value: serde_json::Value =
            serde_json::from_str(&response).expect("structured import reply");
        if value["stage"] != "vpp" || value["result"] != 0 || !value["export_error"].is_null() {
            std::process::exit(1);
        }
        return;
    }
    if command == "sni-query" {
        if remaining.len() != 3 {
            usage();
        }
        let worker = remaining[0].parse().unwrap_or_else(|_| usage());
        let slot = remaining[1].parse().unwrap_or_else(|_| usage());
        let incarnation = remaining[2].parse().unwrap_or_else(|_| usage());
        match core.query_sni(worker, slot, incarnation) {
            Ok(s) => {
                println!("sni.code=0\nsni.generation={}\nsni.worker={}\nsni.slot={}\nsni.incarnation={}\nsni.result={}\nsni.stop={}\nsni.attempts={}\nsni.bytes={}\nsni.work={}\nsni.cache_bytes={}\nsni.protocols={}\nsni.protocols_available={}\nsni.name={}",
                    s.generation,s.worker,s.slot,s.incarnation,s.result,s.stop,s.attempts,s.bytes,
                    s.work,s.cache_bytes,s.protocols,s.protocols_available,
                    String::from_utf8_lossy(&s.name[..s.name_length as usize]));
            }
            Err(e) => {
                print_error(e);
                std::process::exit(1);
            }
        }
        return;
    }
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
            "rule-replace-all" | "rule-network-disable" if remaining.len() == 2 => {
                request.operation = if command == "rule-network-disable" {
                    3
                } else {
                    2
                };
                request.expected_saved_revision = number(0);
                let text = std::fs::read_to_string(&remaining[1]).unwrap_or_else(|_| usage());
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    request.push_line(line).unwrap_or_else(|error| {
                        eprintln!("configuration: {error}");
                        usage()
                    });
                }
            }
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
                println!("config.count={}\nconfig.active_count={}\nconfig.error_index={}\nconfig.compiler_status={}",
                    s.count, s.active_count, s.error_index, s.compiler_status);
                println!(
                    "config.domain_list_count={}\nconfig.domain_entry_count={}",
                    s.domains.list_count, s.domains.entry_count
                );
                for (i, entry) in s.domains.entries[..s.domains.entry_count as usize]
                    .iter()
                    .enumerate()
                {
                    println!("config.domain.{i}.list={}\nconfig.domain.{i}.mode={}\nconfig.domain.{i}.name={}",
                        entry.list, entry.mode, String::from_utf8_lossy(&entry.name[..entry.length as usize]));
                }
                for (i, r) in s.rules[..s.count as usize].iter().enumerate() {
                    println!("config.rule.{i}.version={}\nconfig.rule.{i}.uid={}\nconfig.rule.{i}.family={}\nconfig.rule.{i}.protocol={}\nconfig.rule.{i}.action={}", r.version, r.uid, r.family, r.protocol, r.action);
                    println!("config.rule.{i}.expression_length={}", r.expression_length);
                    println!(
                        "config.rule.{i}.expression={}",
                        r.expression
                            .iter()
                            .take(r.expression_length.min(64) as usize)
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                }
                for (i, version) in s.active_versions[..s.active_count as usize]
                    .iter()
                    .enumerate()
                {
                    println!("config.active_version.{i}={version}");
                }
                println!(
                    "config.group_count={}\nconfig.edge_count={}\nconfig.binding_count={}",
                    s.graph.group_count, s.graph.edge_count, s.graph.binding_count
                );
                for (i, id) in s.graph.groups[..s.graph.group_count as usize]
                    .iter()
                    .enumerate()
                {
                    println!("config.group.{i}={id}");
                }
                for (i, e) in s.graph.edges[..s.graph.edge_count as usize]
                    .iter()
                    .enumerate()
                {
                    println!("config.edge.{i}={},{},{}", e.group, e.kind, e.target);
                }
                for (i, b) in s.graph.bindings[..s.graph.binding_count as usize]
                    .iter()
                    .enumerate()
                {
                    println!(
                        "config.binding.{i}={},{},{},{},{}",
                        b.id, b.uid, b.kind, b.target, b.mode
                    );
                }
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
