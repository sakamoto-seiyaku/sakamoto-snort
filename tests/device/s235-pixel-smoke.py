#!/usr/bin/env python3
"""Same-source Pixel Root smoke; actual RuntimeService hooks and JNI stop."""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('s235_supervisor', ROOT/'tests/device/s242-pixel-supervisor.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
save, digest = base.save, base.digest


class Campaign(base.Campaign):
    def __init__(self, args, build, helper):
        super().__init__(args, build, helper)
        self.result.update(task='SAKAMOTO-235', scope='Pixel-Root-same-source-smoke',
                           smoke_runner_sha256=digest(__file__))
        save(args.output/'smoke-runner.py', Path(__file__).read_text())

    def run(self):
        self.prepare()
        record = self.start_app('smoke', 0)
        self.policy(record, 1)
        for seed in record['seeds']:
            if seed['owner_path'] == 'local':
                self.probe(record, seed['family'], seed['host'], 'policy-drop', False, seed['source_port'])
        self.policy(record, 0)
        for seed in record['seeds']:
            if seed['owner_path'] == 'local':
                self.probe(record, seed['family'], seed['host'], 'recover', True, seed['source_port'])
        self.app_stop(record)
        save(self.args.output/'network-events.log', self.target.adb(
            'logcat', '-d', '-s', 'SakamotoNetwork:I', '*:S').stdout)
        self.result['status'] = 'RAW_COMPLETE'
        print('Pixel Root same-source smoke complete', flush=True)


def main():
    parser = argparse.ArgumentParser()
    for name in ('build', 'helpers', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(); args.platform = 'pixel'
    for name in ('build', 'helpers', 'output'): setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert helper['build_sha256'] == digest(args.build) and helper['platform'] == 'pixel'
    campaign = Campaign(args, build, helper)
    try: campaign.run()
    except Exception as error:
        campaign.result['error'] = repr(error)
        raise
    finally: campaign.cleanup()


if __name__ == '__main__': main()
