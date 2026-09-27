#!/usr/bin/env python3
"""Independent T27 source, packet, storage and retention evidence checks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("chain", ROOT / "tests/evidence/product_chain.py")
chain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chain)

p = argparse.ArgumentParser()
p.add_argument("--evidence", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
base = a.evidence.resolve()


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def persistent(path):
    return read(path)["consumer"]["persistent"]


def verify_sqlite(path, require_auto_vacuum=True):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", path
        if require_auto_vacuum:
            assert db.execute("PRAGMA auto_vacuum").fetchone()[0] == 1, path
        pages = db.execute("PRAGMA page_count").fetchone()[0]
        width = db.execute("PRAGMA page_size").fetchone()[0]
        assert path.stat().st_size == pages * width, path
        return pages * width
    finally:
        db.close()


linux_build_path = base / "linux-build-final/build.json"
pixel_build_path = base / "pixel-build-final/build.json"
linux_build, pixel_build = read(linux_build_path), read(pixel_build_path)
source_hash = linux_build["source_sha256"]
assert source_hash == pixel_build["source_sha256"]
assert chain.source_files() == linux_build["files"] == pixel_build["files"]
for build_path, build in ((linux_build_path, linux_build), (pixel_build_path, pixel_build)):
    assert hashlib.sha256(chain.encode(build["files"])).hexdigest() == source_hash
    assert digest(build_path.parent / "dirty.diff") == build["dirty_diff_sha256"]
    for name, expected in build["files"].items():
        snapshot = build_path.parent / "source" / name
        assert (not snapshot.exists()) if expected is None else digest(snapshot) == expected, snapshot
assert digest(Path(pixel_build["apk"])) == pixel_build["apk_sha256"]
for name, expected in linux_build["artifact_hashes"].items():
    assert digest(Path(linux_build["artifact"]) / name) == expected
linux = base / "linux-history-final2"
linux_raw = read(linux / "result.json")
assert linux_raw["status"] == "RAW_COMPLETE" and linux_raw["task"] == "T26"
assert linux_raw["source_sha256"] == source_hash
assert linux_raw["build_sha256"] == digest(linux_build_path)
assert all(digest(linux / name) == value for name, value in linux_raw["files"].items())
packet_oracle = read(base / "linux-history-verification-final.json")
assert packet_oracle["status"] == "VALID"
assert packet_oracle["actual_packet_paths"] == 12
assert packet_oracle["actual_policy_drops"] == 2
assert len(packet_oracle["mutations_rejected"]) == 6

controlled = base / "linux-controlled-final-source-b"
control = read(controlled / "result.json")
assert control["status"] == "PASS"
assert Path(control["source_database"]).resolve() == (linux / "observation/overall.sqlite3").resolve()
before, hourly, daily, expired = (control["age"][name]
    for name in ("before", "hourly", "daily", "expired"))
for q in (before, hourly, daily, expired):
    assert q["packets"] == [7, 5] and q["bytes"] == [644, 460]
    assert q["persistence"]["pending"] is False and q["save_error"] is None
    assert q["storage_space"]["within_budget"] is True
assert [before["stored_minute_count"], hourly["stored_minute_count"],
        daily["stored_minute_count"], expired["stored_minute_count"]] == [1, 0, 0, 0]
assert [hourly["hour_windows"]["counts"]["overall"],
        daily["day_windows"]["counts"]["overall"],
        expired["day_windows"]["counts"]["overall"]] == [1, 1, 0]
assert expired["coverage"]["evicted"]["packets"] == [7, 5]
assert before["coverage"]["gaps"] == 2 and expired["coverage"]["gaps"] == 2
pressure = control["pressure"]
assert pressure["before"]["recent_count"] == 1
assert pressure["after"]["recent_count"] == 0
assert pressure["after"]["packets"] == [7, 5]
assert pressure["after"]["stored_minute_count"] == 1
assert pressure["after"]["coverage"]["evicted"]["packets"] == [0, 0]
assert pressure["after"]["storage_space"]["within_budget"] is True
host_database_bytes = {name: verify_sqlite(controlled / name / "overall.sqlite3")
                       for name in ("age", "pressure")}

batch_dir = base / "batch-schedules-final"
batch = read(batch_dir / "result.json")
assert [row["batch_records"] for row in batch] == [64, 256, 1000]
assert [row["flush_after_each_caller_batch"] for row in batch] == [True, True, False]
assert batch[0]["write_commits"] > batch[1]["write_commits"] > batch[2]["write_commits"]
assert batch[0]["write_checkpoints"] > batch[1]["write_checkpoints"] > batch[2]["write_checkpoints"]
assert [row["maintenance_flushes"] for row in batch] == [7, 7, 7]
for row in batch:
    assert row["packets"] == [1000, 0] and row["within_budget"] is True
    assert row["query_us_median"] > 0 and row["query_us_p90"] >= row["query_us_median"]
    assert row["commits"] >= 1 and row["wal_peak_bytes"] > 0
    assert row["database_and_index_bytes"] == verify_sqlite(
        batch_dir / f"batch-{row['batch_records']}" / "overall.sqlite3")

maintenance_dir = base / "maintenance-schedules-verified"
maintenance = read(maintenance_dir / "result.json")
assert [row["trigger"] for row in maintenance] == ["idle_tick", "receipt_call"]
assert [row["commits_during_trigger"] for row in maintenance] == [0, 1]
assert [row["maintenance_flushes"] for row in maintenance] == [8, 7]
assert maintenance[0]["staged_rows_before_first_flush"] > 0
assert maintenance[1]["staged_rows_before_first_flush"] == 0
for row in maintenance:
    assert row["packets"] == [1000, 0] and row["within_budget"] is True
    assert row["database_and_index_bytes"] == verify_sqlite(
        maintenance_dir / row["trigger"] / "overall.sqlite3")

pixel_summaries = {}
expected_original = None
for profile in ("root", "vpn"):
    run = base / f"pixel-{profile}-verified"
    result = read(run / "result.json")
    assert result["status"] == "RAW_COMPLETE" and result["task"] == "T27"
    assert result["profile"] == profile and result["scenario"] == "retention"
    assert result["source_sha256"] == source_hash
    assert result["build_sha256"] == digest(pixel_build_path)
    assert result["apk_sha256"] == pixel_build["apk_sha256"]
    assert result["native_sha256"] == pixel_build["native_sha256"]
    installed_native = {Path(line.split()[1]).name:line.split()[0]
        for line in (run / "installed-native.txt").read_text().splitlines()}
    assert installed_native == pixel_build["native_sha256"]
    assert all(digest(run / name) == value for name, value in result["files"].items())
    assert digest(run / "t27-pixel-retention.py") == digest(ROOT / "tests/device/t27-pixel-retention.py")
    assert digest(run / "s233-fail-open.py") == digest(ROOT / "tests/device/s233-fail-open.py")
    original_before = read(run / "before-original-hashes.json")
    original_after = read(run / "after-original-hashes.json")
    assert original_before == original_after
    if expected_original is None:
        expected_original = original_before
    assert original_after == expected_original
    assert all(value and len(value) == 64 for value in original_after.values())
    assert len(result["lifetimes"]) == 5
    assert all(item["process_absent"] and item["service_process_absent"]
               for item in result["lifetimes"])
    allow, drop = (read(run / f"{name}-traffic.json") for name in ("allow", "drop"))
    assert [allow["sent"], allow["received"], drop["sent"], drop["received"]] == [2, 2, 2, 0]
    host_pcap = (run / "host.pcap").read_bytes()
    for exchange in allow["exchanges"]:
        assert exchange["echoed"] and host_pcap.count(bytes.fromhex(exchange["payload"])) == 2
    for exchange in drop["exchanges"]:
        assert not exchange["echoed"] and bytes.fromhex(exchange["payload"]) not in host_pcap
    assert result["selected_rule_packets"] == 2 and result["pressure_reclaimed"] is True
    assert result["idle_wake_cost"]["seconds"] == 5
    assert 0 <= result["idle_wake_cost"]["waits_delta"] <= 2
    allow_q = persistent(run / "allow.json")
    drop_q = persistent(run / "drop.json")
    pressure_q = persistent(run / "pressure-baseline.json")
    hour_q = persistent(run / "hour-baseline.json")
    day_q = persistent(run / "day-baseline.json")
    expired_q = persistent(run / "expired-baseline.json")
    assert allow_q["packets"] == [2, 2] and allow_q["stored_minute_count"] == 1
    assert drop_q["packets"] == [4, 2] and drop_q["recent_count"] == 1
    assert drop_q["coverage"]["gaps"] == 0
    assert sum(row["counts"]["packets"][0] for row in drop_q["rule_windows"].values()
        if row["attribution"]["name"] == "allow-request") == 2
    assert any(row["attribution"]["name"] == "drop-request"
        and row["counts"]["packets"][0] == 2
        for row in drop_q["rule_windows"].values())
    assert [q["packets"] for q in (pressure_q, hour_q, day_q, expired_q)] == [[4, 2]] * 4
    assert pressure_q["recent_count"] == 0
    assert pressure_q["hour_windows"]["counts"]["overall"] == 1
    assert hour_q["stored_minute_count"] == 0 and hour_q["hour_windows"]["counts"]["overall"] == 1
    assert day_q["hour_windows"]["counts"]["overall"] == 0
    assert day_q["day_windows"]["counts"]["overall"] == 1
    assert sum(row["counts"]["packets"][0] for row in day_q["day_windows"]["rule_windows"].values()
        if row["attribution"]["name"] == "allow-request") == 2
    assert expired_q["day_windows"]["counts"]["overall"] == 0
    assert expired_q["coverage"]["evicted"]["packets"] == [4, 2]
    assert [q["coverage"]["gaps"] for q in
        (pressure_q, hour_q, day_q, expired_q)] == [1, 2, 3, 4]
    assert expired_q["coverage"]["incomplete"] is True
    assert expired_q["persistence"]["packets"] == [4, 2]
    assert expired_q["persistence"]["pending"] is False
    for q in (allow_q, drop_q, pressure_q, hour_q, day_q, expired_q):
        assert q["save_error"] is None and q["limits"]["scaled_test"] is True
        space = q["storage_space"]
        assert space["within_budget"] is True
        assert sum(space["files"].values()) == space["actual_bytes"]
        assert space["actual_bytes"] + space["working_reserve_bytes"] <= space["budget_bytes"]
    for name in ("initial", "pressure", "hour", "day", "expired"):
        assert verify_sqlite(run / f"{name}.sqlite3") == read(run / f"{name}-storage.json")["database_and_index_bytes"]
        assert read(run / f"{name}-storage.json")["freelist_count"] == 0
        assert read(run / f"{name}-storage.json")["auto_vacuum"] == 1
    assert read(run / "expired-configuration-before-apply.json")["configuration"]["rules"] == []
    pixel_summaries[profile] = {"source_sha256":source_hash,"apk_sha256":result["apk_sha256"],
        "generations":[item["generation"] for item in result["lifetimes"]],
        "selected_rule_packets":2,"totals":expired_q["packets"],
        "evicted":expired_q["coverage"]["evicted"]["packets"],
        "idle_waits_in_5s":result["idle_wake_cost"]["waits_delta"],
        "initial_database_and_index_bytes":(run / "initial.sqlite3").stat().st_size,
        "pressure_database_and_index_bytes":(run / "pressure.sqlite3").stat().st_size,
        "max_observed_owned_bytes":max(q["storage_space"]["actual_bytes"]
            for q in (allow_q, drop_q, pressure_q, hour_q, day_q, expired_q))}

readback = base / "device-readback-verified"
device = read(readback / "summary.json")
assert device["status"] == "PASS"
assert device["source_sha256"] == source_hash
assert device["apk_sha256"] == pixel_build["apk_sha256"]
assert device["ordinary_history_hashes"] == expected_original
prior_device = read(ROOT / "build-output/t26-20260927/device-final-b/summary.json")
assert prior_device["status"] == "PASS"
assert expected_original == {
    "files/observation/overall.sqlite3": prior_device["sqlite_sha256"],
    "files/observation/overall.json": prior_device["legacy_json_sha256"]}
assert device["root_and_vpn_original_history_unchanged"] is True
assert device["sqlite_integrity"] == "ok"
assert digest(readback / "overall.sqlite3") == expected_original["files/observation/overall.sqlite3"]
assert verify_sqlite(readback / "overall.sqlite3", require_auto_vacuum=False) == device["database_and_index_bytes"]
db = sqlite3.connect(f"file:{readback / 'overall.sqlite3'}?mode=ro", uri=True)
try:
    rows = db.execute("SELECT kind,COUNT(*) FROM observation GROUP BY kind ORDER BY kind").fetchall()
finally:
    db.close()
assert [list(row) for row in rows] == device["sqlite_rows"]
state = dict(line.split("=", 1) for line in (readback / "state.properties").read_text().splitlines()
             if "=" in line and not line.startswith("#"))
assert state["state"] == "stopped" and state["mayBeActive"] == "false"
assert int(state["generation"]) == device["stopped_generation"]
assert "libvpp_runtime.so" not in (readback / "processes.txt").read_text()
assert "com.sakamoto.snort.androidruntime:runtime" not in (readback / "processes.txt").read_text()
hooks = (readback / "hooks.txt").read_text()
assert "NFQUEUE" not in hooks and "SAKAMOTO" not in hooks
assert "uid=0" in (readback / "root-grant.txt").read_text()
assert (readback / "installed-apk.txt").read_text().split()[0] == pixel_build["apk_sha256"]
assert device["test_selector_removed"] is True

summary = {"status":"VALID", "source_sha256":source_hash,
    "linux_actual_packet_paths":12,"linux_actual_policy_drops":2,
    "linux_controlled_retained_to_evicted_packets":[7,5],
    "linux_controlled_database_and_index_bytes":host_database_bytes,
    "batch_comparison":batch,"maintenance_comparison":maintenance,"pixel":pixel_summaries,
    "original_android_history_hashes":expected_original,
    "stopped_device_readback":device}
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps({"status":"VALID","source_sha256":source_hash,
    "linux_actual_packet_paths":12,"pixel_profiles":list(pixel_summaries)}, indent=2))
