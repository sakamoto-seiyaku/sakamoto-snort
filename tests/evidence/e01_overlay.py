#!/usr/bin/env python3
"""Apply/restore the explicit E01 measurement overlay, never a release feature.

Builds retain their full overlaid source. Exact old/new hashes and backups make
restoration refuse concurrent source changes instead of overwriting them.
"""
import argparse
import hashlib
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
def digest(data): return hashlib.sha256(data).hexdigest()
def once(text, old, new):
    assert text.count(old) == 1, (old[:100], text.count(old))
    return text.replace(old, new)
def overlay():
    files = {}
    path = 'src/product/vpp/product_observation.c'
    s = (ROOT/path).read_text()
    s = once(s, '#define FLUSH_US UINT64_C (1000000)', '''/* E01 EXPERIMENT ONLY: identical binary, barrier-controlled fresh-run arms. */
static u32 e01_export = 1, e01_growth = 32;
static u64 e01_flush_us = 1000000;
#define FLUSH_US e01_flush_us''')
    s = once(s, '  if (!transport || !entry || slot >= o->capacity) return;',
             '  if (!e01_export || !transport || !entry || slot >= o->capacity) return;')
    s = once(s, '  if (owner >= PRODUCT_OBSERVATION_OWNERS || !entry || !transport) return;',
             '  if (!e01_export || owner >= PRODUCT_OBSERVATION_OWNERS || !entry || !transport) return;')
    s = once(s, 'entry->packets - s->exported_packets >= 32', 'entry->packets - s->exported_packets >= e01_growth')
    s += '''
/* Changes are allowed only before any measured packets: callers verify basic=0. */
static clib_error_t *e01_configure (vlib_main_t *vm, unformat_input_t *input,
                                   vlib_cli_command_t *command) {
  (void) command;
  u32 enabled, growth, flush;
  if (!unformat (input, "export %u growth %u flush %u", &enabled, &growth, &flush)
      || enabled > 1 || (growth != 32 && growth != 128)
      || (flush != 250000 && flush != 1000000))
    return clib_error_return (0, "invalid E01 experiment config");
  vlib_worker_thread_barrier_sync (vm);
  product_observation_status_t status; product_observation_status (&status);
  int active = 0;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; ++i)
    for (unsigned j = 0; j < 3; ++j) active |= status.channels[i].basic_packets[j] != 0;
  if (!active) { e01_export = enabled; e01_growth = growth; e01_flush_us = flush; }
  vlib_worker_thread_barrier_release (vm);
  if (active) return clib_error_return (0, "E01 requires fresh packet-free generation");
  vlib_cli_output (vm, "e01.export=%u growth=%u flush_us=%u", enabled, growth, flush);
  return NULL;
}
VLIB_CLI_COMMAND (e01_observation_config, static) = {
 .path = "product e01 observation", .function = e01_configure,
};
'''
    files[path] = s.encode()
    path = 'crates/product-core/src/observation_service.rs'
    s = (ROOT/path).read_text()
    s = once(s, '        store_error: Option<String>,', '''        store_error: Option<String>,
        e01: E01Metrics,''')
    s = once(s, '    #[derive(Default)]\n    struct Command', '''    #[derive(Default, serde::Serialize)]
    struct E01Metrics {
        batches: u64, records: u64, consume_ns: u64, query_ns: u64,
        max_consume_ns: u64, samples: Vec<(u64, u64, u64)>,
    }
    #[derive(serde::Deserialize)]
    struct E01Config { store: bool, drain: usize, name: String }
    #[derive(Default)]
    struct Command''')
    s = once(s, '            let store_path = store_path.to_owned();', '''            // E01 experiment input is not a Product API. Original history untouched.
            let config: E01Config = serde_json::from_slice(
                &std::fs::read(store_path.with_extension("e01"))
                    .map_err(|e| format!("e01_config:{e}"))?)
                .map_err(|e| format!("e01_config:{e}"))?;
            if ![16,128].contains(&config.drain) || config.name.is_empty()
                || !config.name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err("e01_invalid_config".into());
            }
            let store_path = store_path.with_file_name(format!("e01-{}.json", config.name));''')
    s = once(s, '                store_error: None,', '                store_error: None,\n                e01: E01Metrics::default(),')
    s = once(s, 'let mut store = match ObservationStore::open(&store_path) {',
             'let mut store = if !config.store { None } else { match ObservationStore::open(&store_path) {')
    s = once(s, '                    };\n                    {\n                        let mut s = worker_state', '                    }};\n                    {\n                        let mut s = worker_state')
    s = once(s, 'for _ in 0..128 {', 'for _ in 0..config.drain {')
    s = once(s, '                                let result = store.consume(&records, now);', '''                                let started = std::time::Instant::now();
                                let result = store.consume(&records, now);
                                let elapsed = started.elapsed().as_nanos() as u64;
                                let query_started = std::time::Instant::now();
                                let query = store.query();
                                let query_elapsed = query_started.elapsed().as_nanos() as u64;''')
    s = once(s, '                                s.persistent = store.query();', '''                                s.persistent = query;
                                s.e01.batches += 1;
                                s.e01.records += records.len() as u64;
                                s.e01.consume_ns += elapsed;
                                s.e01.query_ns += query_elapsed;
                                s.e01.max_consume_ns = s.e01.max_consume_ns.max(elapsed);
                                if s.e01.samples.len() < 4096 {
                                    s.e01.samples.push((records.len() as u64, elapsed,
                                        records.iter().map(|r| now.saturating_sub(r.activity_utc_us)).max().unwrap_or(0)));
                                }''')
    files[path] = s.encode()
    path = 'app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProtocolFactsProbe.java'
    s = (ROOT/path).read_text()
    s = once(s, '    private static void observation(Context app',
             (ROOT/'tests/device/helpers/e01_probe.java').read_text()+'\n    private static void observation(Context app')
    s = once(s, 'if (plan.has("observationFlood")) observation(',
             'if (plan.has("e01")) e01(app, plan, result, nonce, endpoint, local, source, port);\n                else if (plan.has("observationFlood")) observation(')
    files[path] = s.encode()
    return files

def main():
    p=argparse.ArgumentParser(); p.add_argument('operation',choices=['apply','restore']); p.add_argument('--state',type=Path,required=True)
    a=p.parse_args(); state=a.state.resolve()
    if a.operation=='apply':
        changes=overlay(); state.mkdir(parents=True,exist_ok=False); manifest={}
        for path,new in changes.items():
            old=(ROOT/path).read_bytes(); backup=state/path; backup.parent.mkdir(parents=True,exist_ok=True); backup.write_bytes(old)
            manifest[path]={'before':digest(old),'after':digest(new)}
        (state/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        for path,new in changes.items(): (ROOT/path).write_bytes(new)
    else:
        manifest=json.loads((state/'manifest.json').read_text())
        for path,row in manifest.items():
            assert digest((ROOT/path).read_bytes())==row['after'], 'concurrent change: '+path
            assert digest((state/path).read_bytes())==row['before']
        for path in manifest: (ROOT/path).write_bytes((state/path).read_bytes())
    print(json.dumps({'operation':a.operation,'files':list(manifest)}))
if __name__=='__main__': main()
