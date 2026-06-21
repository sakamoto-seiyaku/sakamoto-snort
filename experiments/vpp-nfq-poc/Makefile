.PHONY: build-smoke docker-build docker-shell fetch-vpp apply-vpp-overlay apply-vpp-android-overlay build-vpp smoke-accept smoke-drop smoke-ratio idle-cpu vpp-idle-cpu vpp-nfqueue-cli-check vpp-nfqueue-accept vpp-nfqueue-drop vpp-nfqueue-ratio vpp-nfqueue-idle-cpu android-preflight android-vpp-configure-probe android-vpp-build-probe android-vpp-build-nfqueue-plugin android-vpp-stage-core android-vpp-push-core android-vpp-version-probe android-vpp-minimal-probe setup-netns cleanup-netns collect-cpu

IMAGE ?= sakamoto-vpp-nfq-poc:dev

build-smoke:
	./scripts/build-smoke.sh

docker-build:
	docker build -t $(IMAGE) .

docker-shell:
	./scripts/run-container.sh bash

fetch-vpp:
	./scripts/fetch-vpp.sh

apply-vpp-overlay:
	./scripts/apply-vpp-overlay.sh

apply-vpp-android-overlay:
	./scripts/apply-vpp-android-overlay.sh

build-vpp:
	./scripts/build-vpp.sh

setup-netns:
	./scripts/setup-netns.sh up

cleanup-netns:
	./scripts/setup-netns.sh down

smoke-accept:
	./scripts/run-smoke.sh accept-all

smoke-drop:
	./scripts/run-smoke.sh drop-all

smoke-ratio:
	./scripts/run-smoke.sh drop-ratio=50

idle-cpu:
	./scripts/run-idle-cpu.sh

vpp-idle-cpu:
	./scripts/run-vpp-idle-cpu.sh

vpp-nfqueue-cli-check:
	./scripts/run-vpp-nfqueue-cli-check.sh

vpp-nfqueue-accept:
	./scripts/run-vpp-nfqueue-smoke.sh accept-all

vpp-nfqueue-drop:
	./scripts/run-vpp-nfqueue-smoke.sh drop-all

vpp-nfqueue-ratio:
	./scripts/run-vpp-nfqueue-smoke.sh drop-ratio=50

vpp-nfqueue-idle-cpu:
	./scripts/run-vpp-nfqueue-idle-cpu.sh

android-preflight:
	./scripts/android-preflight.sh

android-vpp-configure-probe:
	./scripts/android-configure-vpp-probe.sh

android-vpp-build-probe:
	./scripts/android-build-vpp-probe.sh

android-vpp-build-nfqueue-plugin:
	TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh

android-vpp-stage-core:
	./scripts/android-stage-vpp-core.sh

android-vpp-push-core:
	./scripts/android-push-vpp-core.sh

android-vpp-version-probe:
	./scripts/android-run-vpp-version.sh

android-vpp-minimal-probe:
	./scripts/android-run-vpp-minimal.sh

collect-cpu:
	./scripts/collect-cpu.sh
