#!/usr/bin/env python3
"""Current Product observation transport: Host/native Rust, sanitizer and ARM builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
p = argparse.ArgumentParser()
p.add_argument("--output",type=Path,required=True)
p.add_argument("--host-artifact",type=Path,required=True)
p.add_argument("--host-stage",type=Path,required=True)
p.add_argument("--android-stage",type=Path,required=True)
p.add_argument("--android-cc",type=Path,required=True)
a = p.parse_args()
out = a.output.resolve(); out.mkdir(parents=True,exist_ok=False)
artifact = a.host_artifact.resolve(); stage = a.host_stage.resolve(); android = a.android_stage.resolve()
include = stage/"source/build-root/install-vpp-native/vpp/include"
native = ROOT/"src/product/native/product_observation_transport.c"
env = dict(os.environ,LD_LIBRARY_PATH=str(artifact/"lib"))
digest = lambda file:hashlib.sha256(Path(file).read_bytes()).hexdigest()
result = dict(started_ns=time.time_ns(),status="HOLD",commands=[],
              host_artifact=str(artifact),android_stage=str(android))
sources = ["src/product/native/product_observation_transport.c", "src/product/include/sakamoto_product_observation.h",
           "crates/product-core/src/observation.rs", "crates/product-core/src/observation_service.rs",
           "crates/product-core/src/observation_store.rs", "generated/rust/application_protocol_catalog.rs",
           "crates/product-core/tests/observation_store.rs", "tests/host/product_observation_transport_test.c",
           "tests/host/product_observation_handshake_test.c", "tests/host/product_observation_producer.c", "tests/host/t23_query_delay.c"]
result["source_hashes"] = {name:digest(ROOT/name) for name in sources}
for name in sources:
    destination = out/"source"/name; destination.parent.mkdir(parents=True,exist_ok=True)
    destination.write_bytes((ROOT/name).read_bytes())

def run(label,command,environment=env):
    with (out/(label+".log")).open("w") as log:
        completed = subprocess.run(list(map(str,command)),env=environment,cwd=ROOT,
                                   stdout=log,stderr=subprocess.STDOUT)
    result["commands"].append(dict(label=label,argv=list(map(str,command)),exit_code=completed.returncode))
    assert completed.returncode == 0,label

try:
    common = ["cc","-std=gnu11","-Wall","-Wextra","-Werror","-fno-strict-aliasing",
              "-I"+str(ROOT/"src/product/include"),"-isystem",str(include)]
    libraries = ["-L"+str(artifact/"lib"),"-lsvm","-lvppinfra","-lpthread","-ldl","-lm"]
    for name in ("transport_test","handshake_test","producer"):
        run(name+"-build",common+[ROOT/f"tests/host/product_observation_{name}.c",native,
                                  *libraries,"-o",out/name])
    run("transport-test",[out/"transport_test"])
    run("handshake-test",[out/"handshake_test",f"/tmp/t22-handshake-{os.getpid()}.sock"])
    run("query-delay-build", ["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
        ROOT/"tests/host/t23_query_delay.c", "-ldl", "-o", out/"query-delay.so"])
    live = dict(env,LD_PRELOAD=str(out/"query-delay.so"),
                SAKAMOTO_QUERY_DELAY_ARM=str(out/"query-delay.arm"),SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR=str(include),
                SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR=str(artifact/"lib"),
                SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR=str(artifact/"include/vapi"),
                SAKAMOTO_OBSERVATION_PRODUCER=str(out/"producer"))
    run("rust-native",["cargo","test","-p","sakamoto-product-core","--lib","native_",
                       "--","--ignored","--nocapture","--test-threads=1"],live)
    run("sanitize-build",common+["-g","-fno-omit-frame-pointer","-no-pie","-fsanitize=address,undefined",
        ROOT/"tests/host/product_observation_transport_test.c",native,*libraries,"-o",out/"transport-sanitize"])
    sanitized = dict(env,ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",UBSAN_OPTIONS="halt_on_error=1")
    run("sanitize",[out/"transport-sanitize"],sanitized)
    arm = [str(a.android_cc.resolve()),"-std=gnu11","-Wall","-Wextra","-Werror","-fno-strict-aliasing",
           "-I"+str(ROOT/"src/product/include"),"-isystem",str(android/"include")]
    for name in ("transport_test","handshake_test"):
        run("arm64-"+name+"-build",arm+[ROOT/f"tests/host/product_observation_{name}.c",native,
            "-L"+str(android/"lib"),"-lsvm","-lvppinfra","-ldl","-lm","-o",out/(name+"-arm64")])
    assert result["source_hashes"] == {name:digest(ROOT/name) for name in sources},"source changed during checks"
    result["status"] = "PASS"
    result["instrumented"] = "Product C transport and boundary test; pinned shared libraries uninstrumented"
    result["arm64_runtime"] = "not run by this builder"
finally:
    result["completed_ns"] = time.time_ns()
    result["files"] = {str(file.relative_to(out)):digest(file) for file in out.rglob("*") if file.is_file()}
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps({key:result[key] for key in ("status","instrumented","arm64_runtime")},indent=2))
