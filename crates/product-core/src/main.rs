use sakamoto_product_core::{ErrorCode, ProductCore, ProductError, Status};
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
}

fn usage() -> ! {
    eprintln!("usage: sakamoto-product-core-host query <api-socket> <generation>");
    std::process::exit(2);
}

fn main() {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("query") {
        usage();
    }
    let Some(socket) = arguments.next() else {
        usage()
    };
    let Some(generation) = arguments.next() else {
        usage()
    };
    if arguments.next().is_some() {
        usage();
    }
    let generation: u64 = generation.parse().unwrap_or_else(|_| usage());
    let (mut core, connected) = match ProductCore::connect(Path::new(&socket), generation) {
        Ok(value) => value,
        Err(error) => {
            print_error(error);
            std::process::exit(1);
        }
    };
    print_status("connect", &connected);
    let queried = match core.query() {
        Ok(status) => status,
        Err(error) => {
            print_error(error);
            std::process::exit(1);
        }
    };
    print_status("query", &queried);
    if queried.code != ErrorCode::Ok
        || !queried.core_ready
        || queried.adapter_available
        || queried.protection_running
    {
        eprintln!("product core did not report the Host-only readiness contract");
        std::process::exit(1);
    }
}

fn print_error(error: ProductError) {
    eprintln!("product core error: {error:?}");
}
