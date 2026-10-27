//! One generation-owned consumer. All mapping access remains on its thread.
#[cfg(product_vapi)]
mod live {
    use crate::observation::{FlowRecord, ObservationHealth, Overview};
    use crate::dns_observation::DnsRecord;
    use crate::observation_store::ObservationStore;
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::path::Path;
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};

    unsafe extern "C" {
        fn product_observation_connect_for_owners(
            path: *const c_char, generation: u64, owner_count: u32) -> *mut c_void;
        fn product_observation_transport_destroy(handle: *mut c_void);
        fn product_observation_transport_status(handle: *mut c_void, out: *mut ObservationHealth);
        fn product_observation_receive(
            handle: *mut c_void,
            channel: u32,
            out: *mut RawRecord,
            capacity: u32,
        ) -> c_int;
        fn product_observation_wait(handle: *mut c_void, timeout_ms: c_int) -> c_int;
        fn product_observation_interrupt_fd(handle: *mut c_void) -> c_int;
        fn product_observation_interrupt(fd: c_int);
        fn product_observation_close_fd(fd: c_int);
    }
    #[repr(C, align(8))]
    struct RawRecord([u8; 704]);
    #[derive(serde::Serialize)]
    struct State {
        overview: Overview,
        live: bool,
        error: Option<String>,
        waits: u64,
        malformed: u64,
        dns_received: u64,
        store_error: Option<String>,
    }
    #[derive(Default)]
    struct Command {
        stop: bool,
        paused: bool,
        parked: bool,
        finished: bool,
        query_requested: u64,
        query_completed: u64,
        reply: Arc<serde_json::Value>,
        #[cfg(test)]
        shutdown_capture_hook: Option<Box<dyn FnOnce() + Send>>,
    }
    type Control = Arc<(Mutex<Command>, Condvar)>;

    fn capture_query(state: &State, store: Option<&ObservationStore>) -> serde_json::Value {
        let mut reply = serde_json::to_value(state).expect("observation serialization");
        reply["persistent"] = store.map_or(serde_json::Value::Null, ObservationStore::query);
        reply["query_fresh"] = true.into();
        reply["query_error"] = serde_json::Value::Null;
        reply
    }
    fn answer_query(state: &State, store: Option<&ObservationStore>, control: &Control) {
        let (mutex, cv) = &**control;
        let request = {
            let command = mutex.lock().unwrap();
            if command.query_requested == command.query_completed {
                return;
            }
            command.query_requested
        };
        // The consumer owns both sources. Render without the shared control
        // lock so requesters can time out even during a slow projection.
        let reply = Arc::new(capture_query(state, store));
        let mut command = mutex.lock().unwrap();
        command.reply = reply;
        command.query_completed = request;
        cv.notify_all();
    }
    fn unavailable_query(previous: &serde_json::Value, error: &str) -> serde_json::Value {
        let mut reply = if previous.is_object() {
            previous.clone()
        } else {
            serde_json::json!({})
        };
        reply["query_fresh"] = false.into();
        reply["query_error"] = error.into();
        reply
    }

    fn tick_store(state: &mut State, store: &mut Option<ObservationStore>) {
        if let Some(store) = store {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_micros() as u64).unwrap_or(0);
            if let Err(error) = store.tick_real(now) {
                state.store_error = Some(error);
            }
        }
    }

    pub(crate) struct ObservationService {
        control: Control,
        interrupt: c_int,
        thread: Option<JoinHandle<()>>,
    }
    impl std::fmt::Debug for ObservationService {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ObservationService").finish_non_exhaustive()
        }
    }
    impl ObservationService {
        pub(crate) fn start(
            api: &Path,
            generation: u64,
            store_path: &Path,
        ) -> Result<Self, String> {
            Self::start_for_owners(api, generation, store_path, 2)
        }

        pub(crate) fn start_for_owners(
            api: &Path,
            generation: u64,
            store_path: &Path,
            owner_count: u32,
        ) -> Result<Self, String> {
            Self::start_for_owners_with_boot_count(api, generation, store_path, owner_count, None)
        }

        pub(crate) fn start_for_owners_with_boot_count(
            api: &Path,
            generation: u64,
            store_path: &Path,
            owner_count: u32,
            boot_count: Option<u32>,
        ) -> Result<Self, String> {
            if !(1..=62).contains(&owner_count) {
                return Err("invalid_observation_owner_count".into());
            }
            let store_path = store_path.to_owned();
            let path =
                CString::new(format!("{}.obs", api.display())).map_err(|_| "invalid_socket")?;
            let mut worker_state = State {
                overview: Overview::new(generation, 0, 0),
                live: false,
                error: None,
                waits: 0,
                malformed: 0,
                dns_received: 0,
                store_error: None,
            };
            let control: Control = Arc::new((Mutex::new(Command::default()), Condvar::new()));
            let worker_control = control.clone();
            let (tx, rx) = mpsc::sync_channel(1);
            let worker = thread::Builder::new()
                .name("flow-observation".into())
                .spawn(move || {
                    // Native handle never crosses threads. Negotiation and all
                    // mapped queue accesses, including destruction, occur here.
                    let handle = unsafe {
                        product_observation_connect_for_owners(path.as_ptr(), generation, owner_count)
                    };
                    if handle.is_null() {
                        let _ = tx.send(Err("observation_connect_failed".to_owned()));
                        return;
                    }
                    let interrupt = unsafe { product_observation_interrupt_fd(handle) };
                    if interrupt < 0 {
                        unsafe { product_observation_transport_destroy(handle) };
                        let _ = tx.send(Err("observation_interrupt_failed".to_owned()));
                        return;
                    }
                    let mut health = ObservationHealth::default();
                    unsafe { product_observation_transport_status(handle, &mut health) };
                    let mut store = match ObservationStore::open_with_boot_count(&store_path, boot_count)
                        .and_then(|mut store| { store.begin_generation(generation)?; Ok(store) }) {
                        Ok(store) => Some(store),
                        Err(error) => {
                            worker_state.store_error = Some(error);
                            None
                        }
                    };
                    {
                        let s = &mut worker_state;
                        s.overview = Overview::new(
                            generation,
                            health.owners as usize,
                            health.flow_capacity as usize,
                        );
                        s.live = true;
                        s.overview.incomplete = health
                            .channels[..(health.owners as usize * 2)]
                            .iter()
                            .any(|c| c.full != 0 || c.oversize != 0);
                    }
                    if tx.send(Ok(interrupt)).is_err() {
                        unsafe {
                            product_observation_close_fd(interrupt);
                            product_observation_transport_destroy(handle);
                        }
                        return;
                    }
                    let mut coverage_reported = false;
                    let mut shutdown_remaining: Option<Vec<u32>> = None;
                    let mut transport_ended = false;
                    'consume: loop {
                        let (mutex, cv) = &*worker_control;
                        let mut command = mutex.lock().unwrap();
                        while command.paused && !command.stop && !transport_ended {
                            command.parked = true;
                            cv.notify_all();
                            drop(command);
                            tick_store(&mut worker_state, &mut store);
                            answer_query(&worker_state, store.as_ref(), &worker_control);
                            command = mutex.lock().unwrap();
                            if command.query_requested != command.query_completed {
                                continue;
                            }
                            if command.paused && !command.stop {
                                command = cv.wait(command).unwrap();
                            }
                        }
                        command.parked = false;
                        cv.notify_all();
                        if (command.stop || transport_ended) && shutdown_remaining.is_none() {
                            // A disconnect cannot prove producer quiescence.
                            // Preserve the already published prefix, without
                            // following later writes or waiting for an empty
                            // queue. Occupancy is sampled by the sole consumer;
                            // published/consumed counters are not a snapshot.
                            unsafe { product_observation_transport_status(handle, &mut health) };
                            let channels = &health.channels[..(health.owners * 2) as usize];
                            if channels.iter().any(|c| c.occupancy > c.capacity) {
                                worker_state.error = Some("invalid_shutdown_occupancy".into());
                                break;
                            }
                            shutdown_remaining = Some(channels.iter().map(|c| c.occupancy).collect());
                            #[cfg(test)]
                            if let Some(hook) = command.shutdown_capture_hook.take() {
                                hook();
                            }
                        }
                        if shutdown_remaining.as_ref().is_some_and(|n| n.iter().all(|n| *n == 0)) {
                            break;
                        }
                        drop(command);
                        tick_store(&mut worker_state, &mut store);
                        answer_query(&worker_state, store.as_ref(), &worker_control);
                        let mut work = false;
                        let mut records = Vec::new();
                        let mut dns_records = Vec::new();
                        for channel in 0..health.owners * 2 {
                            let limit = shutdown_remaining.as_ref()
                                .map_or(128, |n| n[channel as usize].min(128));
                            for _ in 0..limit {
                                let mut raw = RawRecord([0; 704]);
                                let rv = unsafe {
                                    product_observation_receive(handle, channel, &mut raw, 704)
                                };
                                if rv == 0 {
                                    if let Some(remaining) = &mut shutdown_remaining {
                                        // Never retry a missing captured item.
                                        // The final coverage gap remains real.
                                        worker_state.error = Some("shutdown_prefix_unavailable".into());
                                        remaining[channel as usize] = 0;
                                    }
                                    break;
                                }
                                if rv < 0 {
                                    let s = &mut worker_state;
                                    s.error = Some("invalid_channel_record".into());
                                    s.overview.incomplete = true;
                                    break 'consume;
                                }
                                if let Some(remaining) = &mut shutdown_remaining {
                                    remaining[channel as usize] -= 1;
                                }
                                work = true;
                                if raw.0[3] == 16 {
                                    match DnsRecord::decode(&raw.0) {
                                        Some(record) if channel % 2 == 0
                                            && record.owner as u32 == channel / 2
                                            && record.generation == generation
                                            && (record.slot == u32::MAX || record.slot < health.flow_capacity) => {
                                                worker_state.dns_received += 1;
                                                dns_records.push(record);
                                            }
                                        _ => {
                                            worker_state.malformed += 1;
                                            worker_state.overview.incomplete = true;
                                        }
                                    }
                                    continue;
                                }
                                {
                                    let s = &mut worker_state;
                                    match FlowRecord::decode(&raw.0) {
                                        Some(record)
                                            if record.owner as u32 == channel / 2
                                                && record.blocked == (channel % 2 == 1)
                                                && record.generation == generation
                                                && record.slot < if record.blocked {
                                                    health.blocked_capacity
                                                } else {
                                                    health.flow_capacity
                                                } =>
                                        {
                                            s.overview.consume(record.clone());
                                            records.push(record);
                                        }
                                        _ => {
                                            s.malformed += 1;
                                            s.overview.incomplete = true;
                                        }
                                    }
                                }
                            }
                        }
                        unsafe { product_observation_transport_status(handle, &mut health) };
                        if health
                            .channels[..(health.owners as usize * 2)]
                            .iter()
                            .any(|c| c.full != 0 || c.oversize != 0 || c.notify_errors != 0
                                || c.allocation_lost != 0)
                        {
                            worker_state.overview.incomplete = true;
                        }
                        if let Some(store) = &mut store {
                            let newly_incomplete = !coverage_reported
                                && worker_state.overview.incomplete;
                            if newly_incomplete {
                                store.mark_gap();
                                coverage_reported = true;
                            }
                            if !records.is_empty() || !dns_records.is_empty() || newly_incomplete || store.has_pending() {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_micros() as u64)
                                    .unwrap_or(0);
                                let result = store.consume_real(&records, now);
                                if let Err(error) = result {
                                    worker_state.store_error = Some(error);
                                }
                                if !dns_records.is_empty() {
                                    if let Err(error) = store.consume_dns_real(&dns_records, now) {
                                        worker_state.store_error = Some(error);
                                    }
                                }
                            }
                        }
                        if !work && shutdown_remaining.is_none() {
                            worker_state.waits += 1;
                            let timeout =
                                store.as_ref().map_or(-1, ObservationStore::wait_timeout_ms);
                            if unsafe { product_observation_wait(handle, timeout) } < 0 {
                                // Peer closure may race the empty check in
                                // C's wait. Capture the published prefix on the
                                // next pass, as for an explicit disconnect.
                                transport_ended = true;
                            }
                        }
                    }
                    {
                        let s = &mut worker_state;
                        s.live = false;
                        // The producer may still publish, and this consumer
                        // cannot prove quiescence or drain completion. Even an
                        // empty overview can hide an entire queued lifecycle.
                        s.overview.incomplete = true;
                        if let Some(store) = &mut store {
                            if s.overview.incomplete {
                                store.mark_gap();
                            }
                            if let Err(error) = store.close() {
                                s.store_error = Some(error);
                            }
                        }
                    }
                    unsafe { product_observation_transport_destroy(handle) };
                    let (mutex, cv) = &*worker_control;
                    let reply = Arc::new(capture_query(&worker_state, store.as_ref()));
                    let mut command = mutex.lock().unwrap();
                    command.reply = reply;
                    command.query_completed = command.query_requested;
                    command.finished = true;
                    cv.notify_all();
                })
                .map_err(|e| e.to_string())?;
            match rx.recv() {
                Ok(Ok(interrupt)) => Ok(Self {
                    control,
                    interrupt,
                    thread: Some(worker),
                }),
                result => {
                    let _ = worker.join();
                    Err(format!("{result:?}"))
                }
            }
        }
        pub(crate) fn snapshot(&self) -> serde_json::Value {
            let (mutex, cv) = &*self.control;
            let mut command = mutex.lock().unwrap();
            if !command.finished {
                let Some(request) = command.query_requested.checked_add(1) else {
                    return unavailable_query(
                        &command.reply,
                        "observation_query_sequence_exhausted",
                    );
                };
                command.query_requested = request;
                cv.notify_all(); // Also serves a deliberately paused consumer.
                unsafe { product_observation_interrupt(self.interrupt) };
                command = cv
                    .wait_timeout_while(command, std::time::Duration::from_secs(2), |c| {
                        c.query_completed < request && !c.finished
                    })
                    .unwrap()
                    .0;
                if command.query_completed < request && !command.finished {
                    let reply = command.reply.clone();
                    drop(command);
                    return unavailable_query(&reply, "observation_query_timeout");
                }
            }
            // The reply was captured as one consistent view by the store's
            // owning consumer. New packets cannot mutate that projection.
            let reply = command.reply.clone();
            drop(command);
            (*reply).clone()
        }
        pub(crate) fn pause(&self, paused: bool) {
            let (mutex, cv) = &*self.control;
            let mut command = mutex.lock().unwrap();
            command.paused = paused;
            cv.notify_all();
            unsafe { product_observation_interrupt(self.interrupt) };
            while !command.finished && command.parked != paused {
                command = cv.wait(command).unwrap();
            }
        }
    }
    impl Drop for ObservationService {
        fn drop(&mut self) {
            let (mutex, cv) = &*self.control;
            mutex.lock().unwrap().stop = true;
            cv.notify_all();
            unsafe { product_observation_interrupt(self.interrupt) };
            if let Some(worker) = self.thread.take() {
                let _ = worker.join();
            }
            unsafe { product_observation_close_fd(self.interrupt) };
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{BufRead, BufReader, Write};
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        #[test]
        #[ignore = "requires actual source-linked Root Adapter records and Product C transport producer"]
        fn native_root_dns_proxy_identity_and_delivery_survive_sqlite_reopen() {
            let root = std::env::temp_dir().join(format!("s315-observation-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let records = std::env::var("SAKAMOTO_DNS_PROXY_RECORDS").unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped())
                .spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "dns-proxy {records}").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "DNS-PROXY 31");
            let check = |reply: &serde_json::Value| {
                assert_eq!(reply["storage"], "sqlite");
                assert_eq!(reply["dns"]["accepted"], 31);
                assert_eq!(reply["dns"]["rejected"], 0);
                let rows = reply["dns"]["recent"].as_object().unwrap();
                assert_eq!(rows.len(), 31, "no query/response/return identity may overwrite another");
                for row in rows.values() {
                    let record = &row["record"];
                    assert_eq!(record["uid"], 10123);
                    assert_eq!(record["resolver_port"], 53);
                    assert_eq!(record["upstream_address"][0], 198);
                    assert_eq!(record["upstream_port"], 53);
                    assert_eq!(record["adapter_profile"], 1);
                    assert_ne!(record["request_attempt"], 0);
                    assert_ne!(record["proxy_flags"].as_u64().unwrap() & 1, 0);
                }
                for family in [4, 6] {
                    let delivered = rows.values().find(|r| r["record"]["family"] == family
                        && r["record"]["stage"] == 4 && r["record"]["reply_rcode"] == 3).unwrap();
                    let record = &delivered["record"];
                    assert_eq!(record["id"], 0x1234);
                    assert_eq!(record["rcode"], 3, "actual upstream NXDOMAIN is separate from local error source");
                    assert_eq!(record["delivery"], 2);
                    assert_eq!(record["return_provenance"], 5);
                    assert_eq!(record["return_policy_revision"], 7);
                    assert_ne!(record["return_token"], 0);
                    assert_eq!(record["query_policy_revision"], 3);
                    assert!(rows.values().any(|r| r["record"]["family"] == family
                        && r["record"]["stage"] == 4 && r["record"]["caller"] == 0
                        && r["record"]["delivery"] == 3 && r["record"]["return_winner"] == 999));
                    assert!(rows.values().any(|r| r["record"]["family"] == family
                        && r["record"]["stage"] == 4 && r["record"]["delivery"] == 4));
                }
                let changed = rows.values().find(|r| r["record"]["stage"] == 4
                    && r["record"]["winner"] == 316).unwrap();
                assert_eq!(changed["record"]["query_policy_revision"], 3);
                assert_eq!(changed["record"]["policy_revision"], 5);
                assert_eq!(changed["record"]["reply_rcode"], 5);
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let snapshot = service.snapshot();
                if snapshot["persistent"]["dns"]["accepted"] == 31 {
                    check(&snapshot["persistent"]); break;
                }
                assert!(Instant::now() < deadline, "Root proxy records were not accepted: {snapshot}");
                thread::sleep(Duration::from_millis(10));
            }
            drop(service);
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            check(&restored.query()); drop(restored);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires source-linked Root TCP Adapter records and Product C transport producer"]
        fn native_root_tcp_proxy_identity_and_view_failure_survive_sqlite_reopen() {
            let root = std::env::temp_dir().join(format!("s317-observation-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let records = std::env::var("SAKAMOTO_DNS_TCP_PROXY_RECORDS").unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "dns-proxy {records}").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "DNS-PROXY 24");
            let check = |reply: &serde_json::Value| {
                assert_eq!(reply["storage"], "sqlite");
                assert_eq!(reply["dns"]["accepted"], 24);
                assert_eq!(reply["dns"]["rejected"], 0);
                let rows = reply["dns"]["recent"].as_object().unwrap();
                assert_eq!(rows.len(), 24, "each TCP query, resolution and delivery must retain its identity");
                for family in [4, 6] {
                    let delivered: Vec<_> = rows.values().filter(|r| r["record"]["family"] == family
                        && r["record"]["stage"] == 4).map(|r| &r["record"]).collect();
                    assert_eq!(delivered.len(), 4);
                    for record in &delivered {
                        assert_eq!(record["protocol"], 6);
                        assert_eq!(record["uid"], 10123);
                        assert_eq!(record["caller"], 1);
                        assert_eq!(record["packet_uid"], u32::MAX);
                        assert_eq!(record["packet_availability"], 0);
                        assert_eq!(record["message_sequence"], record["token"]);
                        assert_eq!(record["reply_capacity"], 65535);
                        assert_eq!(record["delivery"], 2);
                        assert_eq!(record["return_provenance"], 0, "socket delivery is not a fabricated VPP return");
                        assert_eq!(record["return_policy_revision"], 0);
                    }
                    assert!(delivered.iter().any(|r| r["reply_rcode"] == 5 && r["winner"] == 317));
                    assert!(delivered.iter().any(|r| r["reply_rcode"] == 2 && r["proxy_result"] == 9));
                    assert!(delivered.iter().any(|r| r["reply_rcode"] == 0 && r["upstream_port"] == 53053));
                }
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let snapshot = service.snapshot();
                if snapshot["persistent"]["dns"]["accepted"] == 24 { check(&snapshot["persistent"]); break; }
                assert!(Instant::now() < deadline, "Root TCP proxy records were not committed: {snapshot}");
                thread::sleep(Duration::from_millis(10));
            }
            drop(service);
            writeln!(input, "quit").unwrap(); input.flush().unwrap(); assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap(); check(&restored.query());
            drop(restored); std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual Product C producer executable"]
        fn native_tcp_dns_frames_and_continuation_survive_sqlite_reopen() {
            check_native_tcp_dns_frames("dns-tcp", 1);
        }

        #[test]
        #[ignore = "requires the actual Product C producer executable"]
        fn native_vpn_tcp_dns_frames_and_continuation_survive_sqlite_reopen() {
            check_native_tcp_dns_frames("dns-vpn-tcp", 2);
        }

        fn check_native_tcp_dns_frames(command: &str, profile: u64) {
            let root = std::env::temp_dir().join(format!("s313-observation-{}-{profile}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped())
                .spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "{command}").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "DNS-TCP 11");
            let check = |reply: &serde_json::Value| {
                assert_eq!(reply["storage"], "sqlite");
                assert_eq!(reply["dns"]["accepted"], 11);
                assert_eq!(reply["dns"]["rejected"], 0);
                let rows = reply["dns"]["recent"].as_object().unwrap();
                assert_eq!(rows.len(), 11);
                let queries: Vec<_> = rows.values().filter(|r| r["record"]["token"] == 17).collect();
                assert_eq!(queries.len(), 2, "coalesced frames share a packet token without overwriting");
                assert!(queries.iter().any(|r| r["record"]["message_sequence"] == 1 && r["record"]["tcp_sequence"] == 101));
                assert!(queries.iter().any(|r| r["record"]["message_sequence"] == 2 && r["record"]["tcp_sequence"] == 132));
                let malformed: Vec<_> = rows.values().filter(|r| r["record"]["token"] == 23).collect();
                assert_eq!(malformed.len(), 2, "coalesced malformed frames keep separate persisted identities");
                assert!(malformed.iter().any(|r| r["record"]["message_sequence"] == 1 && r["record"]["tcp_sequence"] == 601));
                assert!(malformed.iter().any(|r| r["record"]["message_sequence"] == 2 && r["record"]["tcp_sequence"] == 606));
                for row in malformed { assert_eq!(row["record"]["coverage"], 2); }
                let alias = rows.values().find(|r| r["record"]["token"] == 18 && r["record"]["name_source"] == 1).unwrap();
                assert_eq!(alias["record"]["name"], "alias.test");
                let continuation = rows.values().find(|r| r["record"]["token"] == 22).unwrap();
                let record = &continuation["record"];
                assert_eq!(record["stage"], 2);
                assert_eq!(record["direction"], 1);
                assert_eq!(record["packet_direction"], 3);
                assert_eq!(record["tcp_continuation"], 1);
                assert_eq!(record["query_token"], 17);
                assert_eq!(record["query_policy_revision"], 3);
                assert_eq!(record["policy_revision"], 9);
                assert_eq!(record["actual_action"], 2);
                for row in rows.values() {
                    assert_eq!(row["record"]["protocol"], 6);
                    assert_eq!(row["record"]["adapter_profile"], profile);
                    if profile == 2 && row["record"]["correlation"] == 1 && row["record"]["stage"] == 2 {
                        assert_eq!(row["record"]["transport_session"], 71);
                        assert_eq!(row["record"]["underlay_epoch"], 9);
                        assert_eq!(row["record"]["query_incarnation"], 8);
                    }
                }
            };
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let snapshot = service.snapshot();
                if snapshot["persistent"]["dns"]["accepted"] == 11 {
                    check(&snapshot["persistent"]); break;
                }
                assert!(Instant::now() < deadline, "normal consumer did not accept TCP records: {snapshot}");
                thread::sleep(Duration::from_millis(10));
            }
            drop(service);
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            check(&restored.query()); drop(restored);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual Product C producer executable"]
        fn native_dns_reply_query_and_alias_identities_survive_sqlite_reopen() {
            let root = std::env::temp_dir().join(format!("s312-observation-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped())
                .spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "dns-reply").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "DNS-REPLY 7");
            let deadline = Instant::now() + Duration::from_secs(5);
            let check = |reply: &serde_json::Value| {
                assert_eq!(reply["storage"], "sqlite");
                assert_eq!(reply["dns"]["accepted"], 7);
                assert_eq!(reply["dns"]["rejected"], 0);
                let rows = reply["dns"]["recent"].as_object().unwrap();
                assert_eq!(rows.len(), 7);
                let query = rows.values().find(|r| r["record"]["stage"] == 1).unwrap();
                assert_eq!(query["record"]["policy_revision"], 3);
                assert_eq!(query["record"]["winner"], 310);
                for row in rows.values().filter(|r| r["record"]["token"] == 18) {
                    let record = &row["record"];
                    assert_eq!(record["stage"], 2);
                    assert_eq!(record["query_token"], 17);
                    assert_eq!(record["query_policy_revision"], 3);
                    assert_eq!(record["policy_revision"], 9);
                    assert_eq!(record["winner"], 312);
                    assert_eq!(record["actual_action"], 2);
                    assert_eq!(record["delivery"], 0);
                }
                let alias = rows.values().find(|r| r["record"]["token"] == 18 && r["record"]["name_source"] == 1).unwrap();
                assert_eq!(alias["record"]["name"], "alias.test");
                for row in rows.values().filter(|r| r["record"]["token"] == 19) {
                    assert_eq!(row["record"]["caller"], 0);
                    assert_eq!(row["record"]["correlation"], 3);
                    assert_eq!(row["record"]["query_token"], 0);
                }
                for (token, coverage) in [(20, 2), (21, 5)] {
                    let row = rows.values().find(|r| r["record"]["token"] == token).unwrap();
                    let record = &row["record"];
                    assert_eq!(record["stage"], 2);
                    assert_eq!(record["query_flags"], 0);
                    assert_eq!(record["coverage"], coverage);
                    assert_eq!(record["name"], "");
                    assert_eq!(record["correlation"], 2);
                    assert_eq!(record["caller"], 0);
                    assert_eq!(record["query_token"], 0);
                }
            };
            loop {
                let snapshot = service.snapshot();
                if snapshot["persistent"]["dns"]["accepted"] == 7 {
                    check(&snapshot["persistent"]);
                    assert_eq!(snapshot["overview"]["packets"], serde_json::json!([0, 0]));
                    break;
                }
                assert!(Instant::now() < deadline, "normal consumer did not accept reply records: {snapshot}");
                thread::sleep(Duration::from_millis(10));
            }
            drop(service);
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            check(&restored.query());
            drop(restored);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual Product C producer and one-shot WAL delay shim"]
        fn native_query_timeout_returns_qualified_coherent_view_then_recovers() {
            let arm = std::path::PathBuf::from(std::env::var("SAKAMOTO_QUERY_DELAY_ARM").unwrap());
            let hit = std::path::PathBuf::from(format!("{}.hit", arm.display()));
            let root = std::env::temp_dir().join(format!("t23-delay-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs"))
                .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "emit 0 1 456 1 10 0").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "EMITTED 1");
            thread::sleep(Duration::from_millis(1300));
            let first = service.snapshot();
            assert_eq!(first["query_fresh"], true);
            assert_eq!(first["persistent"]["persistence"]["packets"], serde_json::json!([1, 0]));
            std::fs::write(&arm, b"delay next WAL sync").unwrap();
            writeln!(input, "emit 0 1 456 2 10 0").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "EMITTED 1");
            let deadline = Instant::now() + Duration::from_secs(5);
            while !hit.exists() {
                assert!(Instant::now() < deadline, "WAL delay was not exercised");
                thread::sleep(Duration::from_millis(5));
            }
            let started = Instant::now();
            let stale = service.snapshot();
            assert!(started.elapsed() >= Duration::from_millis(1900));
            assert!(started.elapsed() < Duration::from_millis(2800));
            assert_eq!(stale["query_fresh"], false);
            assert_eq!(stale["query_error"], "observation_query_timeout");
            assert_eq!(stale["overview"]["packets"], first["overview"]["packets"]);
            assert_eq!(stale["persistent"], first["persistent"]);
            let recovered = service.snapshot();
            assert_eq!(recovered["query_fresh"], true);
            assert!(recovered["query_error"].is_null());
            assert_eq!(recovered["overview"]["packets"], serde_json::json!([2, 0]));
            assert_eq!(recovered["persistent"]["packets"], serde_json::json!([2, 0]));
            assert_eq!(recovered["persistent"]["persistence"]["packets"], serde_json::json!([2, 0]));
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            drop(service);
            std::fs::remove_dir_all(root).unwrap();
            std::fs::remove_file(hit).unwrap();
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_fresh_queries_work_without_new_packets_while_paused_and_concurrently() {
            let root = std::env::temp_dir().join(format!("t23-query-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service =
                ObservationService::start(&root.join("api"), 77, &root.join("overall.json"))
                    .unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "emit 0 1 456 1 10 0").unwrap();
            input.flush().unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "EMITTED 1");
            // No query owns ingestion or its idle commit deadline.
            thread::sleep(Duration::from_millis(1300));
            service.pause(true);
            let q = service.snapshot();
            assert_eq!(q["query_fresh"], true);
            assert_eq!(q["persistent"]["packets"], serde_json::json!([1, 0]));
            assert_eq!(
                q["persistent"]["persistence"]["packets"],
                serde_json::json!([1, 0])
            );
            thread::scope(|scope| {
                for _ in 0..4 {
                    scope.spawn(|| {
                        for _ in 0..8 {
                            let q = service.snapshot();
                            assert_eq!(q["query_fresh"], true);
                            assert!(q["query_error"].is_null());
                            assert_eq!(q["persistent"]["packets"], serde_json::json!([1, 0]));
                            assert_eq!(q["overview"]["packets"], q["persistent"]["packets"]);
                        }
                    });
                }
            });
            service.pause(false);
            writeln!(input, "emit 0 1 456 2 10 1").unwrap();
            input.flush().unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "EMITTED 1");
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let q = service.snapshot();
                assert_eq!(q["query_fresh"], true);
                assert_eq!(q["overview"]["packets"], q["persistent"]["packets"]);
                if q["persistent"]["ended"] == 1 {
                    break;
                }
                assert!(Instant::now() < deadline);
                thread::sleep(Duration::from_millis(5));
            }
            writeln!(input, "quit").unwrap();
            input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            drop(service);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual Product C transport producer executable"]
        fn native_protocol_labels_survive_transport_query_commit_and_restart() {
            let root = std::env::temp_dir().join(format!("t25-native-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs"))
                .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "protocol").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "PROTOCOL 5");
            let deadline = Instant::now() + Duration::from_secs(5);
            let q = loop {
                let value = service.snapshot();
                if value["persistent"]["ended"] == 1
                    && value["persistent"]["persistence"]["pending"] == false {
                    break value["persistent"].clone();
                }
                assert!(Instant::now() < deadline, "{value}");
                thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(q["packets"], serde_json::json!([5, 2]));
            let rows = q["protocol_windows"].as_object().unwrap();
            let count = |layer: &str, id: u64| rows.values()
                .find(|v| v["layer"] == layer && v["protocol_id"] == id)
                .unwrap()["counts"]["packets"].clone();
            assert_eq!(count("l4", 17), serde_json::json!([5, 2]));
            assert_eq!(count("l7", 1001), serde_json::json!([4, 1]));
            assert_eq!(count("l7", 1006), serde_json::json!([2, 0]));
            assert_eq!(count("l7_none", 0), serde_json::json!([0, 1]));
            assert_eq!(count("l7_unavailable", 0), serde_json::json!([1, 0]));
            assert_eq!(q["rejected"], 1);
            writeln!(input, "protocol-gap").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "PROTOCOL-GAP 2");
            let deadline = Instant::now() + Duration::from_secs(5);
            let gap = loop {
                let value = service.snapshot();
                if value["persistent"]["packets"] == serde_json::json!([10, 2])
                    && value["persistent"]["persistence"]["pending"] == false {
                    break value["persistent"].clone();
                }
                assert!(Instant::now() < deadline, "{value}");
                thread::sleep(Duration::from_millis(5));
            };
            assert!(gap["coverage"]["gaps"].as_u64().unwrap() >= 1);
            assert_eq!(gap["coverage"]["incomplete"], true);
            assert_eq!(gap["l4_unknown"]["packets"], serde_json::json!([2, 0]));
            assert_eq!(gap["l7_unknown"]["packets"], serde_json::json!([3, 0]));
            let rows = gap["protocol_windows"].as_object().unwrap();
            let count = |id: u64| rows.values().find(|v| v["layer"] == "l7" && v["protocol_id"] == id)
                .unwrap()["counts"]["packets"].clone();
            assert_eq!(count(1001), serde_json::json!([7, 1]));
            assert_eq!(count(1006), serde_json::json!([4, 0]));
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            drop(service);
            let reopened = ObservationStore::open(&root.join("overall.json")).unwrap();
            assert_eq!(reopened.query()["protocol_windows"], gap["protocol_windows"]);
            drop(reopened);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual Product C transport producer executable"]
        fn native_blocked_and_flow_channels_persist_independent_identities() {
            let root = std::env::temp_dir().join(format!("t24-native-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json"))
                .unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "blocked").unwrap();
            input.flush().unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "BLOCKED 5");
            let deadline = Instant::now() + Duration::from_secs(5);
            let snapshot = loop {
                let value = service.snapshot();
                if value["persistent"]["blocked"]["ended"] == 1
                    && value["persistent"]["persistence"]["pending"] == false {
                    break value;
                }
                assert!(Instant::now() < deadline, "{value}");
                thread::sleep(Duration::from_millis(5));
            };
            assert_eq!(snapshot["overview"]["packets"], serde_json::json!([4, 0]));
            assert_eq!(snapshot["overview"]["blocked_packets"], serde_json::json!([3, 0]));
            assert_eq!(snapshot["persistent"]["blocked"]["packets"], serde_json::json!([3, 0]));
            assert_eq!(snapshot["persistent"]["packets"], serde_json::json!([4, 0]));
            assert_eq!(snapshot["persistent"]["rule_windows"].as_object().unwrap().len(), 2);
            assert_eq!(snapshot["persistent"]["application_windows"].as_object().unwrap().len(), 2);
            assert_eq!(snapshot["persistent"]["rejected"], 0);
            writeln!(input, "quit").unwrap();
            input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            drop(service);
            let store = ObservationStore::open(&root.join("overall.json")).unwrap();
            assert_eq!(store.query()["blocked"], snapshot["persistent"]["blocked"]);
            drop(store);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_directional_segments_are_atomic_across_transport_and_restart() {
            let root = std::env::temp_dir().join(format!("t23-native-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service =
                ObservationService::start(&root.join("api"), 77, &root.join("overall.json"))
                    .unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            writeln!(input, "attribution").unwrap();
            input.flush().unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "ATTRIBUTION 5");
            let deadline = Instant::now() + Duration::from_secs(5);
            let snapshot = loop {
                let value = service.snapshot();
                if value["persistent"]["rejected"] == 1
                    && value["persistent"]["persistence"]["pending"] == false
                {
                    break value;
                }
                assert!(Instant::now() < deadline, "{value}");
                thread::sleep(Duration::from_millis(5));
            };
            let q = &snapshot["persistent"];
            assert_eq!(q["packets"], serde_json::json!([7, 2]));
            assert_eq!(q["bytes"], serde_json::json!([420, 160]));
            assert_eq!(q["accepted"], 4);
            assert_eq!(q["ended"], 1);
            assert_eq!(
                q["attribution_unknown"]["packets"],
                serde_json::json!([2, 0])
            );
            let rules = q["rule_windows"].as_object().unwrap();
            let rule_packets = |winner| -> [u64; 2] {
                let mut result = [0; 2];
                for row in rules
                    .values()
                    .filter(|v| v["attribution"]["winner"] == winner)
                {
                    for side in 0..2 {
                        result[side] += row["counts"]["packets"][side].as_u64().unwrap();
                    }
                }
                result
            };
            assert_eq!(rule_packets(65537), [3, 0]);
            assert_eq!(rule_packets(131073), [0, 2]);
            assert_eq!(rule_packets(196609), [1, 0]);
            assert!(rules.values().all(|v| v["attribution"]["winner"] != 0));
            assert!(rules
                .values()
                .any(|v| v["attribution"]["name"] == "observe request"
                    && v["attribution"]["declared_action"] == 2
                    && v["attribution"]["actual_action"] == 1));
            writeln!(input, "quit").unwrap();
            input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            drop(service);
            let store = ObservationStore::open(&root.join("overall.json")).unwrap();
            for field in [
                "packets",
                "bytes",
                "minutes",
                "application_windows",
                "rule_windows",
                "attribution_unknown",
                "ended",
            ] {
                assert_eq!(store.query()[field], q[field], "restart changed {field}");
            }
            drop(store);
            std::fs::remove_dir_all(root).unwrap();
        }

        #[test]
        #[ignore = "requires the actual Product C producer and observation poll gate"]
        fn native_shutdown_preserves_stopped_dns_at_producer_disconnect() {
            let root = std::env::temp_dir().join(format!("s319-peer-close-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let directory = std::path::PathBuf::from(std::env::var("SAKAMOTO_SHUTDOWN_WAIT_DIR").unwrap());
            std::fs::create_dir(&directory).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            service.pause(true);
            std::fs::write(directory.join("arm"), b"ARM\n").unwrap();
            service.pause(false);
            let deadline = Instant::now() + Duration::from_secs(5);
            while !directory.join("ready").is_file() {
                assert!(Instant::now() < deadline, "actual C poll boundary not reached");
                thread::sleep(Duration::from_millis(1));
            }
            writeln!(input, "dns-proxy {}", std::env::var("SAKAMOTO_DNS_STOP_PREFIX_RECORDS").unwrap()).unwrap();
            input.flush().unwrap(); line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "DNS-PROXY 16");
            writeln!(input, "status").unwrap(); input.flush().unwrap();
            let mut status = Vec::new();
            for _ in 0..4 {
                line.clear(); output.read_line(&mut line).unwrap();
                status.push(line.trim().to_owned());
            }
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            // Both the real queue publication and peer close happen after
            // C's empty check but before its actual poll. Drop is not requested.
            std::fs::write(directory.join("release"), b"RELEASE\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let final_view = loop {
                let view = service.snapshot();
                if view["live"] == false { break view; }
                assert!(Instant::now() < deadline, "producer-disconnect consumer did not finish");
                thread::sleep(Duration::from_millis(1));
            };
            drop(service);
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            let after = restored.query(); drop(restored);
            let poll: serde_json::Value = serde_json::from_slice(
                &std::fs::read(directory.join("poll-result.json")).unwrap()).unwrap();
            if let Ok(destination) = std::env::var("SAKAMOTO_SHUTDOWN_EVIDENCE_DIR") {
                std::fs::write(Path::new(&destination).join("producer-disconnect.json"),
                    serde_json::to_vec_pretty(&serde_json::json!({
                        "after": after, "final_view": final_view,
                        "producer_channel_status_before_exit": status, "actual_poll": poll,
                        "producer_exited_before_release": true,
                    })).unwrap()).unwrap();
            }
            std::fs::remove_dir_all(root).unwrap();
            let channel: Vec<_> = status[0].split_whitespace().collect();
            assert_eq!(channel[3], "16"); assert_eq!(channel[5], "0"); assert_eq!(channel[6], "16");
            assert_eq!(poll["nfds"], 6); assert_ne!(poll["socket_revents"], 0);
            assert_eq!(after["dns"]["accepted"], 16, "published STOPPED pairs lost on peer close");
            assert_eq!(after["dns"]["rejected"], 0);
            assert_eq!(after["dns"]["recent"].as_object().unwrap().len(), 16);
            assert_eq!(after["coverage"]["incomplete"], true);
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_shutdown_preserves_published_dns_and_flow_prefix() {
            let fixture = std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap();
            let mut failures = Vec::new();
            for (command, expected_dns, profile) in [
                ("dns-reply", 7_u64, 1),
                ("dns-tcp", 11, 1),
                ("dns-vpn-tcp", 11, 2),
            ] {
                let root = std::env::temp_dir().join(format!(
                    "s319-stop-prefix-{}-{command}", std::process::id()));
                std::fs::create_dir(&root).unwrap();
                let mut child = Command::new(&fixture).arg(root.join("api.obs"))
                    .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
                let mut input = child.stdin.take().unwrap();
                let mut output = BufReader::new(child.stdout.take().unwrap());
                let mut line = String::new();
                output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
                let service = ObservationService::start(
                    &root.join("api"), 77, &root.join("overall.json")).unwrap();
                line.clear(); output.read_line(&mut line).unwrap();
                assert_eq!(line.trim(), "CONNECTED");
                service.pause(true);
                for (request, response) in [
                    (command.to_owned(), format!("{} {expected_dns}",
                        if command == "dns-reply" { "DNS-REPLY" } else { "DNS-TCP" })),
                    ("emit 0 260 456 1 10 0".into(), "EMITTED 260".into()),
                    ("emit 2 129 456 1 10 0".into(), "EMITTED 129".into()),
                ] {
                    writeln!(input, "{request}").unwrap(); input.flush().unwrap();
                    line.clear(); output.read_line(&mut line).unwrap();
                    assert_eq!(line.trim(), response);
                }
                let before = service.snapshot();
                assert_eq!(before["dns_received"], 0);
                assert_eq!(before["overview"]["accepted"], 0);
                let started = Instant::now();
                drop(service);
                let elapsed = started.elapsed();
                // The producer remains alive until the consumer has joined;
                // shutdown must not wait for producer exit or future records.
                assert!(child.try_wait().unwrap().is_none());
                writeln!(input, "quit").unwrap(); input.flush().unwrap();
                assert!(child.wait().unwrap().success());
                let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
                let after = restored.query();
                drop(restored);
                if let Ok(directory) = std::env::var("SAKAMOTO_SHUTDOWN_EVIDENCE_DIR") {
                    std::fs::write(Path::new(&directory).join(format!("{command}.json")),
                        serde_json::to_vec_pretty(&serde_json::json!({
                            "before": before, "after": after,
                            "drop_elapsed_us": elapsed.as_micros(),
                            "producer_alive_after_consumer_join": true,
                        })).unwrap()).unwrap();
                }
                let rows = after["dns"]["recent"].as_object().unwrap();
                let qualified = after["dns"]["accepted"] == expected_dns
                    && after["dns"]["rejected"] == 0 && rows.len() == expected_dns as usize
                    && rows.values().all(|row| row["record"]["adapter_profile"] == profile)
                    && after["packets"] == serde_json::json!([389, 0])
                    && after["coverage"]["incomplete"] == true;
                if !qualified { failures.push(format!("{command}: {after}")); }
                std::fs::remove_dir_all(root).unwrap();
            }
            assert!(failures.is_empty(), "published prefix lost on shutdown: {failures:?}");
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_shutdown_preserves_source_linked_stopped_dns_records() {
            let root = std::env::temp_dir().join(format!("s319-stopped-dns-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            service.pause(true);
            writeln!(input, "dns-proxy {}", std::env::var("SAKAMOTO_DNS_STOP_PREFIX_RECORDS").unwrap()).unwrap();
            input.flush().unwrap(); line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "DNS-PROXY 16");
            assert_eq!(service.snapshot()["dns_received"], 0);
            drop(service);
            assert!(child.try_wait().unwrap().is_none());
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            let after = restored.query(); drop(restored);
            if let Ok(directory) = std::env::var("SAKAMOTO_SHUTDOWN_EVIDENCE_DIR") {
                std::fs::write(Path::new(&directory).join("actual-stopped-records.json"),
                    serde_json::to_vec_pretty(&after).unwrap()).unwrap();
            }
            std::fs::remove_dir_all(root).unwrap();
            assert_eq!(after["dns"]["accepted"], 16);
            assert_eq!(after["dns"]["rejected"], 0);
            let rows = after["dns"]["recent"].as_object().unwrap();
            assert_eq!(rows.len(), 16);
            for profile in [1, 2] { for family in [4, 6] { for protocol in [6, 17] {
                let scoped: Vec<_> = rows.values().map(|r| &r["record"]).filter(|r|
                    r["adapter_profile"] == profile && r["family"] == family
                        && r["protocol"] == protocol).collect();
                assert_eq!(scoped.len(), 2, "exact QUERY/STOPPED pair per Adapter/transport/family");
                let query = scoped.iter().find(|r| r["stage"] == 1).unwrap();
                let stopped = scoped.iter().find(|r| r["stage"] == 3).unwrap();
                assert_eq!(stopped["proxy_result"], 8);
                for field in ["generation", "owner", "token", "incarnation", "id", "source_port",
                    "transport_session", "network_revision", "route_revision", "request_attempt"] {
                    assert_eq!(query[field], stopped[field], "stopped record changed {field}");
                }
            } } }
            assert_eq!(after["coverage"]["incomplete"], true);
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_shutdown_does_not_follow_future_producer_writes() {
            let root = std::env::temp_dir().join(format!("s319-stop-future-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap())
                .arg(root.join("api.obs")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "LISTEN");
            let service = ObservationService::start(&root.join("api"), 77, &root.join("overall.json")).unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "CONNECTED");
            service.pause(true);
            writeln!(input, "emit 0 260 456 1 10 0").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "EMITTED 260");
            let (captured, ready) = mpsc::channel();
            let (release, proceed) = mpsc::channel();
            service.control.0.lock().unwrap().shutdown_capture_hook = Some(Box::new(move || {
                captured.send(()).unwrap();
                proceed.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
            let closer = thread::spawn(move || drop(service));
            ready.recv_timeout(Duration::from_secs(5)).unwrap();
            writeln!(input, "emit 0 129 456 261 10 0").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap(); assert_eq!(line.trim(), "EMITTED 129");
            release.send(()).unwrap(); closer.join().unwrap();
            assert!(child.try_wait().unwrap().is_none());
            writeln!(input, "status").unwrap(); input.flush().unwrap();
            let mut status = Vec::new();
            for _ in 0..4 {
                line.clear(); output.read_line(&mut line).unwrap();
                status.push(line.trim().to_owned());
            }
            writeln!(input, "quit").unwrap(); input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            let after = restored.query(); drop(restored);
            if let Ok(directory) = std::env::var("SAKAMOTO_SHUTDOWN_EVIDENCE_DIR") {
                std::fs::write(Path::new(&directory).join("future-prefix.json"),
                    serde_json::to_vec_pretty(&serde_json::json!({
                        "after": after, "producer_channel_status": status,
                        "producer_alive_after_consumer_join": true,
                    })).unwrap()).unwrap();
            }
            std::fs::remove_dir_all(root).unwrap();
            let channel: Vec<_> = status[0].split_whitespace().collect();
            assert_eq!(channel[2], "389", "all initial and later writes actually attempted");
            assert_eq!(channel[3], "389", "all writes actually published");
            assert_eq!(channel[5], "260", "only the initially captured prefix consumed");
            assert_eq!(channel[6], "129", "future writes remain queued");
            assert_eq!(after["packets"], serde_json::json!([260, 0]));
            assert_eq!(after["coverage"]["incomplete"], true);
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_shutdown_with_unseen_queued_flow_preserves_a_coverage_gap() {
            let fixture = std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").unwrap();
            let root = std::env::temp_dir().join(format!("t22-stop-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let mut child = Command::new(fixture)
                .arg(root.join("api.obs"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service =
                ObservationService::start(&root.join("api"), 77, &root.join("overall.json"))
                    .unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            service.pause(true);
            writeln!(input, "emit 0 1 456 1 10 1").unwrap();
            input.flush().unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "EMITTED 1");
            assert_eq!(service.snapshot()["overview"]["accepted"], 0);
            drop(service);
            writeln!(input, "quit").unwrap();
            input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            let restored = ObservationStore::open(&root.join("overall.json")).unwrap();
            assert_eq!(restored.query()["packets"], serde_json::json!([1, 0]));
            let incomplete = restored.query()["coverage"]["incomplete"].clone();
            drop(restored);
            std::fs::remove_dir_all(root).unwrap();
            assert_eq!(incomplete, true, "producer can publish beyond the captured prefix");
        }

        #[test]
        #[ignore = "requires the actual pinned-VPP Product C producer executable"]
        fn native_process_capacity_isolation_end_and_exit() {
            let fixture = std::env::var("SAKAMOTO_OBSERVATION_PRODUCER").expect("producer path");
            let root = std::env::temp_dir().join(format!("t21-{}", std::process::id()));
            std::fs::create_dir(&root).unwrap();
            let api = root.join("api");
            let socket = root.join("api.obs");
            let mut child = Command::new(fixture)
                .arg(&socket)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = child.stdin.take().unwrap();
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "LISTEN");
            let service =
                ObservationService::start(&api, 77, &root.join("observation.json")).unwrap();
            line.clear();
            output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "CONNECTED");
            let mut emit = |command: &str| -> u64 {
                writeln!(input, "{command}").unwrap();
                input.flush().unwrap();
                let mut reply = String::new();
                output.read_line(&mut reply).unwrap();
                reply
                    .strip_prefix("EMITTED ")
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap()
            };
            let wait = |predicate: &dyn Fn(&serde_json::Value) -> bool| {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    let snapshot = service.snapshot();
                    if predicate(&snapshot) {
                        break snapshot;
                    }
                    assert!(Instant::now() < deadline, "consumer timeout: {snapshot}");
                    thread::sleep(Duration::from_millis(5));
                }
            };
            assert_eq!(emit("emit 0 2 456 1 10 0"), 2);
            wait(&|s| s["overview"]["packets"][0] == 2);
            service.pause(true);
            assert_eq!(emit("emit 1 600 456 1 10 0"), 512);
            assert_eq!(emit("emit 0 600 456 3 10 0"), 512);
            assert_eq!(emit("emit 2 125 480 1 20 0"), 125);
            assert_eq!(service.snapshot()["overview"]["packets"][0], 2);
            service.pause(false);
            let s = wait(&|s| s["overview"]["packets"][0] == 639);
            assert_eq!(s["overview"]["bytes"][0], 38340);
            assert_eq!(s["overview"]["active"], 2);
            assert_eq!(s["overview"]["incomplete"], true);
            assert_eq!(emit("emit 0 1 480 515 10 1"), 1);
            let s = wait(&|s| s["overview"]["ended"] == 1);
            assert_eq!(s["overview"]["packets"][0], 640);
            assert_eq!(s["overview"]["bytes"][0], 38400);
            assert_eq!(emit("emit 0 1 456 514 10 0"), 1);
            assert_eq!(emit("emit 0 1 480 515 10 1"), 1);
            let s = wait(&|s| s["overview"]["rejected"] == 2);
            assert_eq!(s["overview"]["active"], 1);
            assert_eq!(s["overview"]["packets"][0], 640);
            let durable = wait(&|s| s["persistent"]["rejected"] == 2);
            assert_eq!(durable["persistent"]["packets"][0], 640);
            assert_eq!(durable["persistent"]["bytes"][0], 38400);
            assert_eq!(durable["persistent"]["ended"], 1);
            let minutes = durable["persistent"]["minutes"].as_object().unwrap();
            assert_eq!(minutes.len(), 1);
            assert_eq!(minutes.values().next().unwrap()["packets"][0], 640);
            assert_eq!(durable["persistent"]["coverage"]["incomplete"], true);
            // The one-shot pending-tail deadline commits without another
            // producer notification, then the consumer returns to an idle wait.
            wait(&|s| {
                s["persistent"]["persistence"]["packets"][0] == 640
                    && s["persistent"]["persistence"]["pending"] == false
            });
            wait(&|s| s["waits"].as_u64().unwrap() > 0);
            thread::sleep(Duration::from_millis(30));
            let waits = service.snapshot()["waits"].clone();
            thread::sleep(Duration::from_millis(60));
            // A query intentionally wakes the owner once; there is no
            // independent idle polling between these explicit requests.
            assert_eq!(service.snapshot()["waits"], waits.as_u64().unwrap() + 1);
            drop(emit);
            writeln!(input, "quit").unwrap();
            input.flush().unwrap();
            assert!(child.wait().unwrap().success());
            wait(&|s| s["live"] == false);
            drop(service);
            let restored = ObservationStore::open(&root.join("observation.json")).unwrap();
            assert_eq!(restored.query()["packets"][0], 640);
            assert_eq!(restored.query()["ended"], 1);
            drop(restored);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
#[cfg(product_vapi)]
pub(crate) use live::ObservationService;

#[cfg(not(product_vapi))]
#[derive(Debug)]
pub(crate) struct ObservationService;
#[cfg(not(product_vapi))]
impl ObservationService {
    pub(crate) fn start(_: &std::path::Path, _: u64, _: &std::path::Path) -> Result<Self, String> {
        Err("observation_requires_product_vpp".into())
    }
    pub(crate) fn start_for_owners(_: &std::path::Path, _: u64, _: &std::path::Path,
                                   _: u32) -> Result<Self, String> {
        Err("observation_requires_product_vpp".into())
    }
    pub(crate) fn start_for_owners_with_boot_count(_: &std::path::Path, _: u64,
        _: &std::path::Path, _: u32, _: Option<u32>) -> Result<Self, String> {
        Err("observation_requires_product_vpp".into())
    }
    pub(crate) fn snapshot(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    pub(crate) fn pause(&self, _: bool) {}
}
