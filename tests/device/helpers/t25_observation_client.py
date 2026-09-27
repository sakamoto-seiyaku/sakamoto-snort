"""Test-only control for the existing Product observation-serve process."""
import json
import os
from pathlib import Path
import select
import subprocess
import time


class ObservationClient:
    def __init__(self, core, runtime, generation, store, output, env):
        self.output=Path(output)
        store=Path(store);store.parent.mkdir(parents=True,exist_ok=True)
        self.process=subprocess.Popen([str(core),'observation-serve',str(runtime/'api.sock'),
            str(generation),str(store)],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=(self.output/'observation-rust.log').open('w'),bufsize=0)
        startup=[];deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            startup.append(self._line())
            if startup[-1].startswith('observation.ready='):break
        else:raise RuntimeError('observation ready deadline: '+repr(startup))
        (self.output/'observation-startup.txt').write_text('\n'.join(startup)+'\n')

    def _line(self):
        data=bytearray();deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            assert self.process.poll() is None,'observation consumer exited: '+data.decode()
            if select.select([self.process.stdout],[],[],.1)[0]:
                byte=os.read(self.process.stdout.fileno(),1)
                if byte==b'\n':return data.decode()
                assert byte
                data.extend(byte)
        raise RuntimeError('observation response deadline: '+data.decode())

    def query(self,label):
        deadline=time.monotonic()+12
        while True:
            self.process.stdin.write(b'query\n');self.process.stdin.flush()
            text=self._line();assert text.startswith('observation.response='),text
            value=json.loads(text.split('=',1)[1])
            assert value['consumer']['query_fresh'] is True
            if (all(not channel['occupancy'] for channel in value['health']['channels'])
                and not value['consumer']['persistent']['persistence']['pending']):
                (self.output/(label+'-observation.json')).write_text(json.dumps(value,indent=2)+'\n')
                return value
            assert time.monotonic()<deadline,'observation settle '+label
            time.sleep(.05)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write(b'quit\n');self.process.stdin.flush()
            self.process.wait(timeout=10)
        assert self.process.returncode==0
