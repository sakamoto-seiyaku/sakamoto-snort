#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "s125_parse_results", ROOT / "scripts" / "s125-parse-results.py")
PARSER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PARSER)


class S125ParserGoldenTest(unittest.TestCase):
    def test_app_run_id_and_flow_id_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "app.log"
            path.write_text(
                "1 start protocol=udp runId=18446744073709551615\n"
                "2 flow=0 localPort=40000 runId=18446744073709551615 sent=1 "
                "received=1 errors=0 mismatches=0 unexpected=0 reordered=0 fatal=false\n"
                "3 done runId=18446744073709551615 sent=1 received=1 errors=0 "
                "mismatches=0 unexpected=0 reordered=0 fatalFlows=0 "
                "executorTimeout=false\n")
            parsed = PARSER.parse_app(path)
            self.assertEqual(parsed["runId"], 18446744073709551615)
            self.assertEqual(parsed["flows"][0]["flow"], 0)
            self.assertEqual(parsed["done"]["runId"], parsed["runId"])

    def test_steady_delta_and_copy_share(self):
        cell = ROOT / "tests" / "fixtures" / "s125-poc7-cell"
        summary = PARSER.parse_cell(cell)
        self.assertTrue(summary["valid"])
        self.assertEqual(summary["steadySamples"], 2)
        self.assertEqual(summary["observedPathNs"], 370)
        self.assertEqual(summary["observedCopyNsUdp"], 130)
        self.assertAlmostEqual(summary["copyShareUdp"], 130 / 370)

    def test_zero_sent_done_does_not_crash_loss_rate(self):
        with tempfile.TemporaryDirectory() as directory:
            cell = pathlib.Path(directory) / "cell"
            shutil.copytree(ROOT / "tests" / "fixtures" / "s125-poc7-cell", cell)
            (cell / "app.log").write_text(
                "1 start protocol=udp runId=1\n"
                "2 phase warmup-start-nanos=100 steady-start-nanos=200 "
                "steady-end-nanos=400 drain-end-nanos=500\n"
                "3 done runId=1 sent=0 received=0 errors=1 mismatches=0 "
                "unexpected=0 reordered=0 fatalFlows=1 executorTimeout=false\n")
            summary = PARSER.parse_cell(cell)
            self.assertIsNone(summary["lossRate"])

    def test_v2_tcp_without_pure_copy_metric_is_not_decision_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            cell = pathlib.Path(directory)
            (cell / "manifest.json").write_text(json.dumps({
                "schema": "s125-poc7/v2", "label": "tcp-missing-metric",
                "arm": "full", "workers": 1, "protocol": "tcp",
                "flows": 1, "payloadBytes": 33, "burst": 1,
                "load": "closed", "expectEcho": True,
                "observe": "sample64", "simpleperfExpected": False,
            }))
            (cell / "app.log").write_text(
                "1 phase warmup-start-nanos=10 steady-start-nanos=20 "
                "steady-end-nanos=40 drain-end-nanos=50\n"
                "2 done sent=2 received=2 errors=0 mismatches=0 unexpected=0 "
                "reordered=0 fatalFlows=0 executorTimeout=false\n")
            show = []
            for mono, factor in ((25, 1), (35, 2)):
                show.append(
                    f"# cli_monotonic_ns={mono}\n"
                    "s124-vpn-tun-stage mode 0 observe 1 tcp-copy-metric 0 "
                    f"tun-read-ns {100 * factor} tun-read-bytes {3300 * factor} "
                    f"buffer-alloc-ns {50 * factor} ingress-copy-ns {100 * factor} "
                    f"ingress-copy-bytes {3300 * factor} parse-ns {20 * factor} "
                    f"enqueue-ns {30 * factor} enqueue-packets {10 * factor}\n"
                    f"s124-owner 0 started 1 packets {10 * factor} queue-wait-ns "
                    f"{30 * factor} dequeue-to-submit-ns {40 * factor} "
                    f"submit-total-ns {80 * factor}\n"
                    f"s124-owner-perf 0 submit-copy-ns {20 * factor} "
                    f"submit-copy-bytes {3300 * factor} tcp-write-ns {50 * factor} "
                    f"tcp-write-bytes {3300 * factor} tcp-write-calls {10 * factor}\n"
                    "s124-owner-runtime 0 sessions 1 tcp-sessions 1 udp-sessions 0 "
                    "credit-rejects 0\n"
                    "s124-owner-lwip 0 tcp-pcb-used 1 tcp-pcb-free 63\n")
            (cell / "vpp-show.raw").write_text("".join(show))
            resource = ("phase=x\nVmRSS: 1 kB\nVmHWM: 1 kB\n"
                        "--- vpp stat ---\n123 (vpp) S 0 0 0 0 0 0 0 0 0 0 "
                        "0 0 0 0\n")
            for name in ("resource-before.raw", "resource-steady.raw",
                         "resource-after.raw"):
                (cell / name).write_text(resource)
            summary = PARSER.parse_cell(cell)
            self.assertFalse(summary["valid"])
            self.assertFalse(summary["timingReady"])
            self.assertIn("tcp-copy-metric-missing", summary["reasons"])

    def test_v2_observe_off_is_valid_without_copy_attribution(self):
        """The off control measures overhead; zero copy bytes is intentional."""
        with tempfile.TemporaryDirectory() as directory:
            cell = pathlib.Path(directory)
            (cell / "manifest.json").write_text(json.dumps({
                "schema": "s125-poc7/v2", "label": "udp-off-control",
                "arm": "full", "workers": 1, "protocol": "udp",
                "flows": 1, "payloadBytes": 33, "burst": 1,
                "load": "closed", "expectEcho": True, "observe": "off",
                "reconnectEvery": 0, "repeat": 1,
                "simpleperfExpected": False,
            }))
            run_id = 123
            (cell / "app.log").write_text(
                f"1 start protocol=udp runId={run_id}\n"
                "2 phase setup-start-nanos=10 setup-end-nanos=20 "
                "warmup-start-nanos=20 steady-start-nanos=30 "
                "steady-end-nanos=40 drain-end-nanos=50 "
                "teardown-start-nanos=60 teardown-end-nanos=70\n"
                f"3 flow=0 localPort=40000 runId={run_id} sent=1 received=1 "
                "errors=0 mismatches=0 unexpected=0 late=0 reordered=0 fatal=false\n"
                f"4 done runId={run_id} sent=1 received=1 errors=0 mismatches=0 "
                "unexpected=0 late=0 reordered=0 fatalFlows=0 executorTimeout=false "
                "setupStartNanos=10 setupEndNanos=20 teardownStartNanos=60 "
                "teardownEndNanos=70\n")

            stage_fields = {
                "tun-read-calls": 1, "tun-read-bytes": 33,
                "tun-read-eagain": 0, "tun-read-errors": 0,
                "tun-read-ns": 10, "buffer-alloc-calls": 1,
                "buffer-alloc-errors": 0, "buffer-alloc-ns": 5,
                "ingress-copy-ns": 0, "ingress-copy-bytes": 0,
                "parse-packets": 1, "parse-errors": 0, "parse-ns": 2,
                "foreign-packets": 0, "foreign-bytes": 0,
                "tcp-input-checksum-checks": 0,
                "tcp-input-checksum-errors": 0,
                "udp-input-checksum-checks": 1,
                "udp-input-checksum-errors": 0,
                "tcp-output-checksum-checks": 0,
                "tcp-output-checksum-errors": 0,
                "udp-output-checksum-checks": 1,
                "udp-output-checksum-errors": 0,
                "tcp-input-syn-packets": 0,
                "tcp-input-syn-ack-packets": 0,
                "tcp-input-ack-packets": 0,
                "tcp-input-data-packets": 0,
                "tcp-output-syn-packets": 0,
                "tcp-output-syn-ack-packets": 0,
                "tcp-output-ack-packets": 0,
                "tcp-output-data-packets": 0,
                "enqueue-calls": 1, "enqueue-packets": 1,
                "enqueue-drops": 0,
            }

            def stage(factor):
                values = {
                    key: value * factor for key, value in stage_fields.items()
                }
                # Observe-off is represented by zero stage timers/copy bytes;
                # counters still prove that the packet path was exercised.
                for key in ("ingress-copy-ns", "ingress-copy-bytes",
                            "tun-read-ns", "buffer-alloc-ns", "parse-ns",
                            "enqueue-ns"):
                    if key == "enqueue-ns":
                        values[key] = 0
                    elif key != "ingress-copy-bytes":
                        values[key] = 0
                values["enqueue-ns"] = 0
                return " ".join(f"{key} {value}"
                                for key, value in values.items())

            show = []
            for mono, factor in ((31, 1), (39, 2)):
                show.append(
                    f"# cli_monotonic_ns={mono}\n"
                    "show plugins hev_external_driver_poc_plugin.so\n"
                    "s124-vpn-tun-stage mode 0 observe 0 " + stage(factor) + "\n"
                    f"s124-owner 0 started 1 packets {factor} bytes {33 * factor} "
                    f"queue-wait-ns {10 * factor} submit-total-ns {20 * factor}\n"
                    "s124-vpn-tun-output callback-calls " + str(factor)
                    + f" pbuf-bytes {33 * factor} write-calls {factor} "
                    f"write-bytes {33 * factor} partial-writes 0 eagain 0 eintr 0 "
                    "other-errors 0 output-copy-bytes 0\n")
            (cell / "vpp-show.raw").write_text("".join(show))

            resource = (
                "phase=x\n--- vpp status ---\nVmRSS: 1 kB\nVmHWM: 2 kB\n"
                "--- vpp stat ---\n123 (vpp) S 0 0 0 0 0 0 0 0 0 0 1 1 0 0\n"
                "--- app status ---\nVmRSS: 1 kB\nVmHWM: 2 kB\n"
                "--- app stat ---\n124 (app) S 0 0 0 0 0 0 0 0 0 0 1 1 0 0\n"
                "--- thermal ---\ntemp=50000\n")
            for name in ("resource-before.raw", "resource-steady.raw",
                         "resource-after.raw"):
                (cell / name).write_text(resource)
            (cell / "thermal-limit.millic").write_text("65000\n")

            summary = PARSER.parse_cell(cell)
            self.assertTrue(summary["valid"], summary["reasons"])
            self.assertFalse(summary["attributionReady"])
            self.assertIsNone(summary["observedCopyNsUdp"])

    def test_tcp_handshake_gate_is_not_a_payload_slope_cell(self):
        def summary(payload, load, repeat, copy_bytes):
            return {
                "valid": True,
                "timingReady": True,
                "config": {
                    "arm": "full", "observe": "full", "protocol": "tcp",
                    "workers": 1, "flows": 1, "burst": 1,
                    "load": load, "reconnectEvery": 0,
                    "payloadBytes": payload, "repeat": repeat,
                },
                "tcpWriteCopyBytesPerPacket": copy_bytes,
            }

        values = [
            # The gate is a closed p33 cell and must not create a second,
            # incomplete slope group.
            summary(33, "closed", 0, 33.0),
            summary(33, "saturating", 1, 33.0),
            summary(1400, "saturating", 1, 1400.0),
        ]
        rows, slope_pass = PARSER.slope_evidence(values)
        self.assertFalse(slope_pass)  # UDP is required for the final gate.
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["key"],
                         ("tcp", 1, 1, 1, "saturating", 0))
        self.assertTrue(rows[0]["pass"])


if __name__ == "__main__":
    unittest.main()
