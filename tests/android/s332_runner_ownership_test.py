#!/usr/bin/env python3
"""Exercise the device runner's resource contract without an Android device."""
import argparse
import importlib.util
from pathlib import Path
import shlex
import shutil
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("s332_runner", ROOT / "tests/device/s332-debug-query.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
SELECTOR = "files/observation/t27-test.enabled"
RULES = "files/rule-configuration"
TEST_STORE = "files/observation/t27-test"


class DeviceBoundary(runner.Acceptance):
    """A local app filesystem and bounded Android command responses."""
    def __init__(self, directory, fail_at):
        super().__init__(argparse.Namespace(output=directory / "output", serial="fixture",
                         apk=directory / "fixture.apk", endpoint="192.0.2.1"))
        self.device, self.fail_at, self.actions = directory / "device", fail_at, []
        self.state_reads = 0
        for name, data in {RULES + "/rules.conf": b"original rules",
                           TEST_STORE + "/previous.sqlite3": b"previous selected data",
                           "files/observation/overall.json": b"original JSON",
                           "files/observation/overall.sqlite3": b"original SQLite"}.items():
            path = self.device / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

    def state(self, wanted):
        self.state_reads += 1
        if self.fail_at == "snapshot" and self.state_reads == 1:
            raise RuntimeError("snapshot unavailable")
        return {"state": wanted, "mayBeActive": "false", "generation": "1"}

    def app(self, path, binary=False, check=True):
        data = (self.device / path).read_bytes()
        return data if binary else data.decode()

    def adb(self, *args, **kwargs):
        self.actions.append(args)
        if args[:2] == ("shell", "am"):
            if "runtimeStart" in args:
                raise RuntimeError("start response unavailable")
            return "stopped"
        if args[:2] == ("shell", "rm"):
            return ""
        if args[0] == "install" and self.fail_at == "install":
            raise RuntimeError("install unavailable")
        return "ok"

    def shell(self, *args, check=True):
        self.actions.append(args)
        if args[:2] == ("sh", "-c"):
            command = shlex.split(args[2])
            if len(command) == 1:
                command = shlex.split(command[0])
            assert command[:3] == ["test", "!", "-e"], command
            if (self.device / command[3]).exists():
                raise RuntimeError("existing resource: " + command[3])
        elif args[:3] == ("su", "-c", "id"):
            return "uid=0"
        elif args == ("id", "-u"):
            return "12632"
        elif args[0] == "mv":
            if self.fail_at == "second move" and args[1] == TEST_STORE:
                raise RuntimeError("second rename unavailable")
            (self.device / args[1]).rename(self.device / args[2])
        elif args[:2] == ("mkdir", "-p"):
            for name in args[2:]:
                (self.device / name).mkdir(parents=True, exist_ok=True)
        elif args[0] == "touch":
            (self.device / args[1]).touch()
        elif args[:2] == ("rm", "-rf"):
            shutil.rmtree(self.device / args[2], ignore_errors=True)
        elif args[:2] == ("rm", "-f"):
            (self.device / args[2]).unlink(missing_ok=True)
        else:
            raise AssertionError(args)
        return ""


class PeerFixture:
    def __init__(self, *args, **kwargs):
        pass

    def close(self):
        pass

    def bind(self, address):
        pass


class OwnershipTests(unittest.TestCase):
    def exercise(self, fail_at, foreign_selector=False):
        with tempfile.TemporaryDirectory() as temporary:
            test = DeviceBoundary(Path(temporary), fail_at)
            marker = test.device / SELECTOR
            if foreign_selector:
                marker.write_bytes(b"prior selection")
            before = {str(path.relative_to(test.device)): path.read_bytes()
                      for path in test.device.rglob("*") if path.is_file()}
            if fail_at == "peer directory":
                (test.out / "peer-http").mkdir()
            with mock.patch.object(runner, "load", return_value=types.SimpleNamespace(HttpPeer=PeerFixture)), \
                    mock.patch.object(runner.socket, "socket", return_value=PeerFixture()):
                with self.assertRaises((RuntimeError, FileExistsError)):
                    test.run()
            after = {str(path.relative_to(test.device)): path.read_bytes()
                     for path in test.device.rglob("*") if path.is_file()}
            self.assertEqual(before, after)
            starts = [action for action in test.actions if "runtimeStart" in action]
            stops = [action for action in test.actions if "runtimeStop" in action]
            self.assertEqual(len(stops), len(starts))
            self.assertLessEqual(len(starts), 1)
            if foreign_selector:
                self.assertEqual([], starts)
                self.assertFalse(any(action[0] == "install" for action in test.actions))
                self.assertFalse(any(action[:2] == ("shell", "rm") for action in test.actions))
            if fail_at == "snapshot":
                self.assertFalse(starts)
                self.assertFalse(any(action[:2] == ("shell", "rm") for action in test.actions))
            self.assertFalse(test.result.get("cleanup_errors"), test.result)

    def test_existing_selector_is_refused_without_mutation(self):
        self.exercise("install", foreign_selector=True)

    def test_early_snapshot_failure_does_not_stop_or_remove_foreign_state(self):
        self.exercise("snapshot")

    def test_partial_directory_setup_restores_only_acquired_directory(self):
        self.exercise("second move")

    def test_owned_selector_and_directories_are_cleaned_after_setup_failure(self):
        self.exercise("peer directory")

    def test_owned_start_attempt_is_stopped_and_resources_are_restored(self):
        self.exercise("start")


if __name__ == "__main__":
    unittest.main()
