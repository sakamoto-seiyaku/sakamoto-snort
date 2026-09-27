//! One generation-owned consumer. All mapping access remains on its thread.
#[cfg(product_vapi)]
mod live {
    use crate::observation::{FlowRecord, ObservationHealth, Overview};
    use crate::observation_store::ObservationStore;
    use std::ffi::{c_char, c_int, c_void, CString};
    use std::path::Path;
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    use std::thread::{self, JoinHandle};

    unsafe extern "C" {
        fn product_observation_connect(path: *const c_char, generation: u64) -> *mut c_void;
        fn product_observation_transport_destroy(handle: *mut c_void);
        fn product_observation_transport_status(handle: *mut c_void, out: *mut ObservationHealth);
        fn product_observation_receive(
            handle: *mut c_void,
            channel: u32,
            out: *mut RawRecord,
        ) -> c_int;
        fn product_observation_wait(handle: *mut c_void, timeout_ms: c_int) -> c_int;
        fn product_observation_interrupt_fd(handle: *mut c_void) -> c_int;
        fn product_observation_interrupt(fd: c_int);
        fn product_observation_close_fd(fd: c_int);
    }
    #[repr(C, align(8))]
    struct RawRecord([u8; 448]);
    #[derive(serde::Serialize)]
    struct State {
        overview: Overview,
        live: bool,
        error: Option<String>,
        waits: u64,
        malformed: u64,
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
            let store_path = store_path.to_owned();
            let path =
                CString::new(format!("{}.obs", api.display())).map_err(|_| "invalid_socket")?;
            let mut worker_state = State {
                overview: Overview::new(generation, 0, 0),
                live: false,
                error: None,
                waits: 0,
                malformed: 0,
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
                    let handle = unsafe { product_observation_connect(path.as_ptr(), generation) };
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
                    let mut store = match ObservationStore::open(&store_path) {
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
                            .channels
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
                    'consume: loop {
                        let (mutex, cv) = &*worker_control;
                        let mut command = mutex.lock().unwrap();
                        while command.paused && !command.stop {
                            command.parked = true;
                            cv.notify_all();
                            drop(command);
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
                        if command.stop {
                            break;
                        }
                        drop(command);
                        answer_query(&worker_state, store.as_ref(), &worker_control);
                        let mut work = false;
                        let mut records = Vec::new();
                        for channel in 0..4 {
                            for _ in 0..128 {
                                let mut raw = RawRecord([0; 448]);
                                let rv = unsafe {
                                    product_observation_receive(handle, channel, &mut raw)
                                };
                                if rv == 0 {
                                    break;
                                }
                                if rv < 0 {
                                    let s = &mut worker_state;
                                    s.error = Some("invalid_channel_record".into());
                                    s.overview.incomplete = true;
                                    break 'consume;
                                }
                                work = true;
                                if channel % 2 == 0 {
                                    let s = &mut worker_state;
                                    match FlowRecord::decode(&raw.0) {
                                        Some(record)
                                            if record.owner as u32 == channel / 2
                                                && record.generation == generation
                                                && record.slot < health.flow_capacity =>
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
                            .channels
                            .iter()
                            .any(|c| c.full != 0 || c.oversize != 0 || c.notify_errors != 0)
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
                            if !records.is_empty() || newly_incomplete || store.has_pending() {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_micros() as u64)
                                    .unwrap_or(0);
                                let result = store.consume(&records, now);
                                if let Err(error) = result {
                                    worker_state.store_error = Some(error);
                                }
                            }
                        }
                        if !work {
                            worker_state.waits += 1;
                            let timeout =
                                store.as_ref().map_or(-1, ObservationStore::wait_timeout_ms);
                            if unsafe { product_observation_wait(handle, timeout) } < 0 {
                                break;
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
            writeln!(input, "emit 0 1 424 1 10 0").unwrap(); input.flush().unwrap();
            line.clear(); output.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), "EMITTED 1");
            thread::sleep(Duration::from_millis(1300));
            let first = service.snapshot();
            assert_eq!(first["query_fresh"], true);
            assert_eq!(first["persistent"]["persistence"]["packets"], serde_json::json!([1, 0]));
            std::fs::write(&arm, b"delay next WAL sync").unwrap();
            writeln!(input, "emit 0 1 424 2 10 0").unwrap(); input.flush().unwrap();
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
            writeln!(input, "emit 0 1 424 1 10 0").unwrap();
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
            writeln!(input, "emit 0 1 424 2 10 1").unwrap();
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
            writeln!(input, "emit 0 1 424 1 10 1").unwrap();
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
            assert_eq!(restored.query()["packets"], serde_json::json!([0, 0]));
            let incomplete = restored.query()["coverage"]["incomplete"].clone();
            drop(restored);
            std::fs::remove_dir_all(root).unwrap();
            assert_eq!(incomplete, true, "unseen queue was abandoned during stop");
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
            assert_eq!(emit("emit 0 2 424 1 10 0"), 2);
            wait(&|s| s["overview"]["packets"][0] == 2);
            service.pause(true);
            assert_eq!(emit("emit 1 600 424 1 10 0"), 512);
            assert_eq!(emit("emit 0 600 424 3 10 0"), 512);
            assert_eq!(emit("emit 2 125 448 1 20 0"), 125);
            assert_eq!(service.snapshot()["overview"]["packets"][0], 2);
            service.pause(false);
            let s = wait(&|s| s["overview"]["packets"][0] == 639);
            assert_eq!(s["overview"]["bytes"][0], 38340);
            assert_eq!(s["overview"]["active"], 2);
            assert_eq!(s["overview"]["incomplete"], true);
            assert_eq!(emit("emit 0 1 448 515 10 1"), 1);
            let s = wait(&|s| s["overview"]["ended"] == 1);
            assert_eq!(s["overview"]["packets"][0], 640);
            assert_eq!(s["overview"]["bytes"][0], 38400);
            assert_eq!(emit("emit 0 1 424 514 10 0"), 1);
            assert_eq!(emit("emit 0 1 448 515 10 1"), 1);
            let s = wait(&|s| s["overview"]["rejected"] == 2);
            assert_eq!(s["overview"]["active"], 1);
            assert_eq!(s["overview"]["packets"][0], 640);
            let durable = wait(&|s| s["persistent"]["rejected"] == 2);
            assert_eq!(durable["persistent"]["packets"][0], 640);
            assert_eq!(durable["persistent"]["bytes"][0], 38400);
            assert_eq!(durable["persistent"]["ended"], 1);
            assert_eq!(
                durable["persistent"]["minutes"]["1699999980"]["packets"][0],
                640
            );
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
    pub(crate) fn snapshot(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    pub(crate) fn pause(&self, _: bool) {}
}
