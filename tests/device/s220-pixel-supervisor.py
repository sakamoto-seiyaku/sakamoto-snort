#!/usr/bin/env python3
"""Exercise ordered CPU selection through the real Android START/STOP boundary."""
import argparse
import importlib.util
import json
from pathlib import Path
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tests/device'/filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


base = module('s220_service_base', 's242-pixel-supervisor.py')
placement = module('s220_placement_base', 's220-worker-placement.py')
save, digest, rows, props = base.save, base.digest, base.rows, base.props
PREFS = 'shared_prefs/worker-placement.xml'
GUARD = 'files/product-state/s187-worker-core-guardrails.properties'


class Campaign(base.Campaign):
    def __init__(self, args, build, helper):
        super().__init__(args, build, helper)
        self.selection = None
        self.result.update(task='SAKAMOTO-220', scope='Pixel-Root-ordered-CPU-supervisor',
            s220_supervisor_sha256=digest(__file__), placement_runner_sha256=digest(ROOT/'tests/device/s220-worker-placement.py'))
        save(args.output/'s220-supervisor.py', Path(__file__).read_text())

    def action(self, *extras):
        if 'runtimeStart' in extras and self.selection is not None:
            extras = (*extras, '--es', 'runtimeWorkerCpuIds', self.selection)
        return super().action(*extras)

    def affinity(self, record, label):
        placement.Campaign.affinity(self, record, label)

    def request_error(self, record, value, error):
        out = self.args.output/record['label']
        before = self.app('files/logs/runtime-service.log')
        selected = self.selection; self.selection = value
        save(out/('request-'+error+'.txt'), self.action('--ez', 'runtimeStart', 'true', '--es', 'runtimeProfile', 'root'))
        self.selection = selected
        deadline = time.monotonic()+15
        while time.monotonic() < deadline:
            log = self.app('files/logs/runtime-service.log')
            if log.count(' error='+error) > before.count(' error='+error): break
            time.sleep(.1)
        else: raise AssertionError('service did not reject '+value+' as '+error)
        save(out/(error+'.log'), log)
        state = props(save(out/(error+'.properties'), self.app(base.STATE)))
        assert int(state['generation']) == record['generation'] and self.target.alive(record['pid'])
        self.affinity(record, error)
        # Query is read-only and confirms that rejection did not stop protection.
        self.action('--ez', 'debugRefresh', 'true')
        self.wait_state(record, error+'-running', lambda s: s.get('state') == 'running'
                        and s.get('protectionRunning') == 'true' and not s.get('errorCode'))
        original = record['seeds'][0]
        self.probe(record, original['family'], original['host'], error+'-traffic', source_port=original['source_port'])

    def run(self):
        before = save(self.args.output/'preferences-before.xml', self.app(PREFS))
        original = '1,2'
        if before.lstrip().startswith('<?xml'):
            element = ET.fromstring(before).find("string[@name='workerCpuIds']")
            if element is not None: original = element.text
        # Validate only the syntax of a value to restore; native startup still
        # validates its actual CPU availability. Never overwrite an unknown file.
        assert original and len(original.split(',')) == 2 and all(p.isdigit() for p in original.split(','))
        self.result['original_effective_selection'] = original
        self.prepare()
        plan = [('forward', '1,3', [1, 3]), ('saved', None, [1, 3]),
                ('reverse', '3,1', [3, 1]), ('restore', original, list(map(int, original.split(','))))]
        for index, (label, selection, expected) in enumerate(plan):
            self.selection = selection
            record = self.start_app(label, index)
            record.update(worker_cpus=expected, requested_worker_cpus=selection)
            self.affinity(record, 'initial')
            guard = props(save(self.args.output/label/'guard.properties', self.app(GUARD)))
            assert guard['worker_cpu_ids'] == ','.join(map(str, expected)) and guard['worker_core_config_match'] == 'true'
            save(self.args.output/label/'preferences.xml', self.app(PREFS))
            if label == 'forward':
                self.request_error(record, '1,1', 'invalid_worker_cpu_ids')
                self.request_error(record, '3,1', 'worker_placement_requires_restart')
            self.affinity(record, 'active')
            self.snapshot(record, 'before-stop')
            self.app_stop(record)
            print(json.dumps(dict(event='supervisor_generation_collected', case=label,
                generation=record['generation'], cpus=expected)), flush=True)
        self.result['status'] = 'RAW_COMPLETE'


def main():
    parser = argparse.ArgumentParser()
    for name in ('build', 'helpers', 'output'): parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args(); args.platform = 'pixel'; args.main_cpu = 0
    for name in ('build', 'helpers', 'output'): setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(parents=True, exist_ok=False)
    build, helper = json.loads(args.build.read_text()), json.loads(args.helpers.read_text())
    assert placement.chain.source_files() == build['files']
    campaign = Campaign(args, build, helper)
    try: campaign.run()
    except Exception as error:
        campaign.result['error'] = repr(error); raise
    finally: campaign.cleanup()


if __name__ == '__main__': main()
