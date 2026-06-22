.PHONY: build-smoke docker-build docker-shell fetch-vpp fetch-hev build-hev apply-vpp-overlay apply-vpp-android-overlay build-vpp smoke-accept smoke-drop smoke-ratio idle-cpu vpp-idle-cpu vpp-nfqueue-cli-check vpp-nfqueue-accept vpp-nfqueue-drop vpp-nfqueue-ratio vpp-nfqueue-idle-cpu vpp-tun-poc-build vpp-tun-poc-smoke vpp-tun-forward-fd-smoke hev-socketpair-probe android-preflight android-vpp-configure-probe android-vpp-build-probe android-vpp-build-nfqueue-plugin android-vpp-stage-core android-vpp-push-core android-vpp-version-probe android-vpp-minimal-probe android-vpp-configure-trim-nfqueue android-vpp-build-trim-nfqueue android-vpp-stage-trim-nfqueue android-vpp-push-trim-nfqueue android-vpp-minimal-trim-nfqueue android-vpp-build-lite android-vpp-stage-lite android-vpp-push-lite android-vpp-minimal-lite setup-netns cleanup-netns collect-cpu

IMAGE ?= sakamoto-vpp-nfq-poc:dev
ANDROID_TRIM_BUILD_DIR ?= $(CURDIR)/work/vpp-android-trim-nfqueue
ANDROID_TRIM_STAGE_DIR ?= $(CURDIR)/work/android-vpp-trim-nfqueue-stage
ANDROID_LITE_STAGE_DIR ?= $(CURDIR)/work/android-vpp-lite-stage

build-smoke:
	./scripts/build-smoke.sh

docker-build:
	docker build -t $(IMAGE) .

docker-shell:
	./scripts/run-container.sh bash

fetch-vpp:
	./scripts/fetch-vpp.sh

fetch-hev:
	./scripts/fetch-hev.sh

build-hev:
	./scripts/build-hev.sh

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

vpp-tun-poc-build:
	./scripts/apply-vpp-overlay.sh
	TARGET=tun_poc_plugin ./scripts/build-vpp-plugin.sh

vpp-tun-poc-smoke:
	./scripts/run-vpp-tun-poc-smoke.sh

vpp-tun-forward-fd-smoke:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-startup.conf" \
		--log-dir "$(CURDIR)/results"

hev-socketpair-probe:
	./scripts/run-hev-socketpair-probe.sh

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

android-vpp-configure-trim-nfqueue:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" VPP_PLUGINS=nfqueue_poc ./scripts/android-configure-vpp-probe.sh

android-vpp-build-trim-nfqueue:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" TARGET=vppctl ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh

android-vpp-stage-trim-nfqueue:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" STAGE_DIR="$(ANDROID_TRIM_STAGE_DIR)" ./scripts/android-stage-vpp-core.sh

android-vpp-push-trim-nfqueue:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" STAGE_DIR="$(ANDROID_TRIM_STAGE_DIR)" ./scripts/android-push-vpp-core.sh

android-vpp-minimal-trim-nfqueue:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" STAGE_DIR="$(ANDROID_TRIM_STAGE_DIR)" ./scripts/android-run-vpp-minimal.sh

android-vpp-build-lite:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" ./scripts/android-build-vpp-lite.sh

android-vpp-stage-lite:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" STAGE_DIR="$(ANDROID_LITE_STAGE_DIR)" ./scripts/android-stage-vpp-lite.sh

android-vpp-push-lite:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" STAGE_DIR="$(ANDROID_LITE_STAGE_DIR)" STAGE_SCRIPT="$(CURDIR)/scripts/android-stage-vpp-lite.sh" ./scripts/android-push-vpp-core.sh

android-vpp-minimal-lite:
	BUILD_DIR="$(ANDROID_TRIM_BUILD_DIR)" STAGE_DIR="$(ANDROID_LITE_STAGE_DIR)" STAGE_SCRIPT="$(CURDIR)/scripts/android-stage-vpp-lite.sh" ./scripts/android-run-vpp-minimal.sh

collect-cpu:
	./scripts/collect-cpu.sh
