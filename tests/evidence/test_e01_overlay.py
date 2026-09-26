#!/usr/bin/env python3
"""Filesystem-boundary tests: failed overlay application must preserve sources."""
import importlib.util,json,stat,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('overlay',Path(__file__).with_name('e01_overlay.py'))
overlay=importlib.util.module_from_spec(spec);spec.loader.exec_module(overlay)

class OverlayRecovery(unittest.TestCase):
    def test_second_replace_failure_rolls_back_first_and_preserves_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'a').write_bytes(b'old-a');(root/'b').write_bytes(b'old-b')
            (root/'a').chmod(0o640);(root/'b').chmod(0o600)
            replace=overlay.replace_bytes;calls=0
            def fail_second(*args):
                nonlocal calls
                calls+=1
                if calls==2:raise OSError('injected replacement failure')
                return replace(*args)
            with patch.object(overlay,'ROOT',root),patch.object(overlay,'overlay',return_value={'a':b'new-a','b':b'new-b'}),patch.object(overlay,'replace_bytes',side_effect=fail_second),patch.object(sys,'argv',['overlay','apply','--state',str(root/'state')]):
                with self.assertRaisesRegex(OSError,'injected'):overlay.main()
            self.assertEqual((root/'a').read_bytes(),b'old-a');self.assertEqual((root/'b').read_bytes(),b'old-b')
            self.assertEqual(stat.S_IMODE((root/'a').stat().st_mode),0o640)
            self.assertEqual(stat.S_IMODE((root/'b').stat().st_mode),0o600)
            self.assertEqual(list(root.glob('.e01-overlay-*')),[])

    def test_partial_application_can_be_restored_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'state';state.mkdir();manifest={}
            for name in ('a','b'):
                old=('old-'+name).encode();new=('new-'+name).encode()
                (state/name).write_bytes(old);(root/name).write_bytes(new if name=='a' else old)
                manifest[name]={'before':overlay.digest(old),'after':overlay.digest(new),'mode':0o640}
            with patch.object(overlay,'ROOT',root):
                overlay.restore(state,manifest);overlay.restore(state,manifest)
            self.assertEqual((root/'a').read_bytes(),b'old-a');self.assertEqual((root/'b').read_bytes(),b'old-b')

    def test_concurrent_edit_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);state=root/'state';state.mkdir();(state/'a').write_bytes(b'old');(root/'a').write_bytes(b'user-edit')
            manifest={'a':{'before':overlay.digest(b'old'),'after':overlay.digest(b'new'),'mode':0o644}}
            with patch.object(overlay,'ROOT',root):
                with self.assertRaisesRegex(AssertionError,'concurrent change'):overlay.restore(state,manifest)
            self.assertEqual((root/'a').read_bytes(),b'user-edit')
if __name__=='__main__':unittest.main()
