#!/usr/bin/env python3
"""Exercise the real collector ordering with deterministic transport delays."""
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s226_collector', ROOT/'tests/device/s226-expiry-ab.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class Clock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        assert seconds >= 0
        self.value += seconds


class CollectorTiming(unittest.TestCase):
    def exercise(self, arm, preparation_delay=0):
        clock, windows = Clock(), []
        campaign = object.__new__(collector.Campaign)
        temporary = tempfile.TemporaryDirectory(prefix='s226-timing-')
        self.addCleanup(temporary.cleanup)
        campaign.args = SimpleNamespace(output=Path(temporary.name))
        record = dict(case='long', label='long-0-'+arm, arm=arm, generation=22610,
                      count_per_owner=2, pid=123, log='test.log')
        (campaign.args.output/record['label']).mkdir()

        def snapshot(record, label):
            clock.sleep(1.0 + preparation_delay if label == 'seeded' else .3)
            if label == 'seeded':
                return ''.join('flow.entry worker='+str(owner)+'\n' for owner in (0, 0, 1, 1))+\
                    'flow.pool worker=0 entries=2\nflow.pool worker=1 entries=2\n'
            return 'flow.pool entries=0\nexpiry.owner=0 timers=0\nexpiry.owner=1 timers=0\n'

        def cli(record, label, *commands):
            clock.sleep(.4)
            if label == 'enable': return 'expiry.experiment=queued'
            if label == 'initialized': return 'expiry.owner=0 initialize=0\nexpiry.owner=1 initialize=0\n'
            return 'root.lane captured=4\n'

        def run(command, **kwargs):
            if '/s226-monitor ' in command:
                seconds = int(command.split()[-1])/1000
                windows.append((clock.monotonic(), seconds))
                clock.sleep(seconds)
            else:
                clock.sleep(.4)
            return SimpleNamespace(stdout='')

        campaign.target = SimpleNamespace(helpers='/test', run=run,
            read=lambda path: 's226 event=release owner=0\n'*4)
        campaign.seed = lambda record: None
        campaign.snapshot, campaign.cli = snapshot, cli
        campaign.environment = lambda label: clock.sleep(3.0)
        campaign.screen = lambda case: None
        campaign.restore = lambda: None
        with patch.object(collector, 'time', clock):
            campaign.exercise(record)
        return windows

    def test_long_idle_starts_after_quiet_but_finishes_before_real_deadline(self):
        for arm in ('poll', 'deadline'):
            with self.subTest(arm=arm):
                windows = self.exercise(arm)
                begin, duration = windows[0]
                self.assertEqual(duration, 45)
                self.assertGreaterEqual(begin, 11)  # Seed snapshot at t=1, then >=10s without test packets.
                self.assertLess(begin + duration, 60)
                self.assertEqual(windows[1][1], 20)

    def test_slow_preparation_does_not_shorten_registered_observation(self):
        windows = self.exercise('deadline', preparation_delay=8)
        self.assertGreaterEqual(windows[0][0], 19)
        self.assertEqual(windows[0][1], 45)
        # Such a late actual-device window must still be rejected by the
        # independent no-expiry-in-idle check, never rescued with fake time.


class ScreenTransitionTiming(unittest.TestCase):
    def campaign(self, transition_after=2.0):
        clock, windows, commands = Clock(), [], []
        campaign = object.__new__(collector.Campaign)
        temporary = tempfile.TemporaryDirectory(prefix='s226-screen-timing-')
        self.addCleanup(temporary.cleanup)
        campaign.args = SimpleNamespace(output=Path(temporary.name))
        campaign.changed_screen = campaign.changed_doze = False
        state = dict(sleep_at=None, forced=False)

        def adb(*args):
            commands.append(args)
            clock.sleep(.15)
            if args == ('shell', 'input', 'keyevent', '223'):
                state['sleep_at'] = clock.monotonic()
                return SimpleNamespace(stdout='')
            if args == ('shell', 'dumpsys', 'deviceidle', 'force-idle', 'deep'):
                state['forced'] = True
                return SimpleNamespace(stdout='Now forced in to deep idle mode\n')
            off = state['sleep_at'] is not None and clock.monotonic() >= state['sleep_at']+transition_after
            if args == ('shell', 'dumpsys', 'deviceidle'):
                return SimpleNamespace(stdout='mScreenOn='+str(not off).lower()+'\n'+
                    'mForceIdle='+str(state['forced']).lower()+'\n')
            if args == ('shell', 'dumpsys', 'power'):
                # The captured Pixel failure was Dozing but still changing,
                # with deviceidle reporting mScreenOn=true for the old state.
                return SimpleNamespace(stdout='mWakefulness=Dozing\n'+
                    'mWakefulnessChanging='+str(not off).lower()+'\n')
            return SimpleNamespace(stdout='environment\n')

        def run(command, **kwargs):
            self.assertIn('/s226-monitor ', command)
            seconds = int(command.split()[-1])/1000
            windows.append((clock.monotonic(), seconds))
            clock.sleep(seconds)
            return SimpleNamespace(stdout='monitor\n')

        campaign.target = SimpleNamespace(pixel=True, helpers='/test', adb=adb, run=run)
        campaign.cli = lambda *args: 'root.lane captured=4\n'
        return campaign, clock, windows, commands

    def test_screen_transition_finishes_before_environment_snapshot(self):
        for name in ('screen-off', 'forced-doze'):
            with self.subTest(case=name):
                campaign, clock, windows, commands = self.campaign()
                record = dict(case=name, label=name+'-0-deadline', pid=123)
                (campaign.args.output/record['label']).mkdir()
                with patch.object(collector, 'time', clock):
                    campaign.screen(name)
                    campaign.measure(record, 'main', 65, quiet_since=0)
                prefix = campaign.args.output/(record['label']+'-main-before')
                self.assertIn('mScreenOn=false', Path(str(prefix)+'-deviceidle.txt').read_text())
                self.assertIn('mWakefulnessChanging=false', Path(str(prefix)+'-power.txt').read_text())
                self.assertGreaterEqual(windows[0][0], 10)
                self.assertEqual(windows[0][1], 65)
                self.assertEqual(campaign.changed_doze, name == 'forced-doze')

    def test_stuck_screen_transition_does_not_enter_measurement(self):
        campaign, clock, windows, commands = self.campaign(transition_after=1000)
        with patch.object(collector, 'time', clock):
            with self.assertRaisesRegex(RuntimeError, 'screen transition deadline'):
                campaign.screen('screen-off')
        self.assertTrue(campaign.changed_screen)  # Existing finally/restore must still run.
        self.assertFalse(windows)
        self.assertLess(clock.monotonic(), 12)


if __name__ == '__main__':
    unittest.main()
