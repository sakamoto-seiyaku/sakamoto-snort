#!/usr/bin/env python3
"""Apply/restore the explicit E01 measurement overlay, never a release feature.

Builds retain their full overlaid source. Exact old/new hashes and backups make
restoration refuse concurrent source changes instead of overwriting them.
"""
import argparse
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
def digest(data): return hashlib.sha256(data).hexdigest()
def once(text, old, new):
    assert text.count(old) == 1, (old[:100], text.count(old))
    return text.replace(old, new)
def replace_bytes(path, data, mode):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.e01-overlay-', delete=False) as file:
            temporary = Path(file.name)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

def restore(state, manifest):
    for path, row in manifest.items():
        assert digest((ROOT/path).read_bytes()) in (row['before'], row['after']), 'concurrent change: '+path
        assert digest((state/path).read_bytes()) == row['before']
    for path, row in manifest.items():
        current = digest((ROOT/path).read_bytes())
        assert current in (row['before'], row['after']), 'concurrent change: '+path
        if current == row['after']:
            replace_bytes(ROOT/path, (state/path).read_bytes(), row.get('mode', 0o644))

def overlay(probe_source=None, startup_config=True):
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
    if startup_config:
        s = once(s, '#include <time.h>', '#include <time.h>\n#include <stdio.h>')
        s = once(s, 'int product_observation_bind (uint64_t generation, product_flow_runtime_t **runtimes) {', r'''/* E01 test controls are read before adapters can admit their first packet. */
static int e01_startup_config (const char *api, uint64_t generation) {
  char path[4096];
  const char *configured = getenv ("SAKAMOTO_E01_CONFIG");
  if (configured) {
    if (snprintf (path, sizeof (path), "%s", configured) >= (int) sizeof (path)) return 0;
  } else {
    const char *marker = strstr (api, "/files/profiles/");
    if (!marker) return 0;
    size_t prefix = (size_t) (marker - api) + strlen ("/files");
    if (prefix + sizeof ("/observation/overall.e01-native") > sizeof (path)) return 0;
    memcpy (path, api, prefix);
    strcpy (path + prefix, "/observation/overall.e01-native");
  }
  FILE *file = fopen (path, "r");
  if (!file) return 0;
  unsigned enabled, growth, flush; char extra;
  int fields = fscanf (file, "%u %u %u %c", &enabled, &growth, &flush, &extra);
  fclose (file);
  if (fields != 3 || enabled > 1 || (growth != 32 && growth != 128)
      || (flush != 250000 && flush != 1000000)) return 0;
  e01_export = enabled; e01_growth = growth; e01_flush_us = flush;
  fprintf (stderr, "e01.startup generation=%llu export=%u growth=%u flush_us=%u\n",
      (unsigned long long) generation, enabled, growth, flush);
  return 1;
}
int product_observation_bind (uint64_t generation, product_flow_runtime_t **runtimes) {''')
        s = once(s, '  if (!api || strlen (api) + 4 >= sizeof (socket_path)) goto fail;',
                 '  if (!api || strlen (api) + 4 >= sizeof (socket_path) || !e01_startup_config (api, generation)) goto fail;')
        s = once(s, '  u32 enabled, growth, flush;\n  if (!unformat', '''  u32 enabled, growth, flush;
  if (unformat (input, "show")) {
    vlib_cli_output (vm, "e01.export=%u growth=%u flush_us=%u", e01_export, e01_growth, (u32) e01_flush_us);
    return NULL;
  }
  if (!unformat''')
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
             (probe_source if probe_source is not None else (ROOT/'tests/device/helpers/e01_probe.java').read_text())+'\n    private static void observation(Context app')
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
            manifest[path]={'before':digest(old),'after':digest(new),'mode':stat.S_IMODE((ROOT/path).stat().st_mode)}
        (state/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
        try:
            for path,new in changes.items(): replace_bytes(ROOT/path,new,manifest[path]['mode'])
        except BaseException:
            restore(state,manifest)
            raise
    else:
        manifest=json.loads((state/'manifest.json').read_text())
        restore(state,manifest)
    print(json.dumps({'operation':a.operation,'files':list(manifest)}))
if __name__=='__main__': main()
