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
    struct RawRecord([u8; 160]);
    #[derive(serde::Serialize)]
    struct State {
        overview: Overview,
        live: bool,
        error: Option<String>,
        waits: u64,
        malformed: u64,
        persistent: serde_json::Value,
        store_error: Option<String>,
    }
    #[derive(Default)]
    struct Command {
        stop: bool,
        paused: bool,
        parked: bool,
        finished: bool,
    }
    type Control = Arc<(Mutex<Command>, Condvar)>;

    pub(crate) struct ObservationService {
        state: Arc<Mutex<State>>,
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
            let state = Arc::new(Mutex::new(State {
                overview: Overview::new(generation, 0, 0),
                live: false,
                error: None,
                waits: 0,
                malformed: 0,
                persistent: serde_json::Value::Null,
                store_error: None,
            }));
            let control: Control = Arc::new((Mutex::new(Command::default()), Condvar::new()));
            let worker_state = state.clone();
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
                            worker_state.lock().unwrap().store_error = Some(error);
                            None
                        }
                    };
                    {
                        let mut s = worker_state.lock().unwrap();
                        s.overview = Overview::new(
                            generation,
                            health.owners as usize,
                            health.flow_capacity as usize,
                        );
                        s.live = true;
                        if let Some(store) = &store {
                            s.persistent = store.query();
                        }
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
                            command = cv.wait(command).unwrap();
                        }
                        command.parked = false;
                        cv.notify_all();
                        if command.stop {
                            break;
                        }
                        drop(command);
                        let mut work = false;
                        let mut records = Vec::new();
                        for channel in 0..4 {
                            for _ in 0..128 {
                                let mut raw = RawRecord([0; 160]);
                                let rv = unsafe {
                                    product_observation_receive(handle, channel, &mut raw)
                                };
                                if rv == 0 {
                                    break;
                                }
                                if rv < 0 {
                                    let mut s = worker_state.lock().unwrap();
                                    s.error = Some("invalid_channel_record".into());
                                    s.overview.incomplete = true;
                                    break 'consume;
                                }
                                work = true;
                                if channel % 2 == 0 {
                                    let mut s = worker_state.lock().unwrap();
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
                            worker_state.lock().unwrap().overview.incomplete = true;
                        }
                        if let Some(store) = &mut store {
                            let newly_incomplete = !coverage_reported
                                && worker_state.lock().unwrap().overview.incomplete;
                            if newly_incomplete {
                                store.mark_gap();
                                coverage_reported = true;
                            }
                            if !records.is_empty() || newly_incomplete {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_micros() as u64)
                                    .unwrap_or(0);
                                let result = store.consume(&records, now);
                                let mut s = worker_state.lock().unwrap();
                                if let Err(error) = result {
                                    s.store_error = Some(error);
                                }
                                s.persistent = store.query();
                            }
                        }
                        if !work {
                            worker_state.lock().unwrap().waits += 1;
                            if unsafe { product_observation_wait(handle, -1) } < 0 {
                                break;
                            }
                        }
                    }
                    {
                        let mut s = worker_state.lock().unwrap();
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
                            s.persistent = store.query();
                        }
                    }
                    unsafe { product_observation_transport_destroy(handle) };
                    let (mutex, cv) = &*worker_control;
                    mutex.lock().unwrap().finished = true;
                    cv.notify_all();
                })
                .map_err(|e| e.to_string())?;
            match rx.recv() {
                Ok(Ok(interrupt)) => Ok(Self {
                    state,
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
            serde_json::to_value(&*self.state.lock().unwrap()).expect("observation serialization")
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
            writeln!(input, "emit 0 1 136 1 10 1").unwrap();
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
            assert_eq!(emit("emit 0 2 136 1 10 0"), 2);
            wait(&|s| s["overview"]["packets"][0] == 2);
            service.pause(true);
            assert_eq!(emit("emit 1 600 136 1 10 0"), 512);
            assert_eq!(emit("emit 0 600 136 3 10 0"), 512);
            assert_eq!(emit("emit 2 125 160 1 20 0"), 125);
            assert_eq!(service.snapshot()["overview"]["packets"][0], 2);
            service.pause(false);
            let s = wait(&|s| s["overview"]["packets"][0] == 639);
            assert_eq!(s["overview"]["bytes"][0], 38340);
            assert_eq!(s["overview"]["active"], 2);
            assert_eq!(s["overview"]["incomplete"], true);
            assert_eq!(emit("emit 0 1 160 515 10 1"), 1);
            let s = wait(&|s| s["overview"]["ended"] == 1);
            assert_eq!(s["overview"]["packets"][0], 640);
            assert_eq!(s["overview"]["bytes"][0], 38400);
            assert_eq!(emit("emit 0 1 136 514 10 0"), 1);
            assert_eq!(emit("emit 0 1 160 515 10 1"), 1);
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
            // No periodic timeout rescues notifications or creates idle spins.
            wait(&|s| s["waits"].as_u64().unwrap() > 0);
            thread::sleep(Duration::from_millis(30));
            let waits = service.snapshot()["waits"].clone();
            thread::sleep(Duration::from_millis(60));
            assert_eq!(service.snapshot()["waits"], waits);
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
