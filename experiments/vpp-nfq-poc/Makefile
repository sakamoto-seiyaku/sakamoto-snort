.PHONY: build-smoke docker-build docker-shell fetch-vpp fetch-hev build-hev apply-vpp-overlay apply-vpp-android-overlay build-vpp smoke-accept smoke-drop smoke-ratio smoke-ipv6-accept smoke-ipv6-drop smoke-ipv6-ratio poc-rules-cli-check android-package-rules-json android-list-user-packages-json android-package-block-poc android-vpn-owner-uid-poc android-vpn-owner-uid-ipv6-poc android-vpn-owner-gate-poc android-vpn-owner-gate-ipv6-poc android-vpn-owner-gate-udp-poc android-vpn-owner-gate-udp-ipv6-poc android-vpp-hev-handoff-poc android-vpp-hev-handoff-ipv4-drop-poc android-vpp-hev-handoff-redirect-poc android-vpp-owner-resolver-poc android-vpp-owner-resolver-cache-poc android-vpp-owner-resolver-uid-drop-poc android-vpp-owner-resolver-ipv6-uid-drop-poc android-vpp-owner-resolver-redirect-uid-drop-poc android-vpp-owner-resolver-ipv6-redirect-uid-drop-poc android-vpp-owner-resolver-udp-drop-poc android-vpp-owner-resolver-udp-redirect-drop-poc android-vpp-owner-resolver-udp-cache-burst-poc android-vpp-owner-resolver-ipv6-udp-drop-poc android-vpp-owner-resolver-ipv6-udp-redirect-drop-poc idle-cpu vpp-idle-cpu vpp-nfqueue-cli-check vpp-nfqueue-accept vpp-nfqueue-drop vpp-nfqueue-ratio vpp-nfqueue-ipv6-accept vpp-nfqueue-ipv6-drop vpp-nfqueue-ipv6-ratio vpp-nfqueue-ipv6-block-peer vpp-nfqueue-ipv6-block-miss vpp-nfqueue-ipv6-events vpp-nfqueue-idle-cpu vpp-tun-poc-build vpp-tun-poc-api-status-smoke vpp-tun-poc-smoke vpp-tun-forward-fd-smoke vpp-tun-worker-thread-smoke vpp-tun-handoff-probe-smoke vpp-tun-handoff-forward-fd-smoke vpp-tun-handoff-forward-fd-redirect-smoke vpp-tun-handoff-forward-fd-ipv4-drop vpp-tun-handoff-forward-fd-ipv4-miss vpp-tun-handoff-forward-fd-ipv6-drop vpp-tun-handoff-tuple-smoke vpp-tun-handoff-tuple-ipv6-smoke vpp-tun-handoff-resolver-smoke vpp-tun-handoff-resolver-uid-drop vpp-tun-handoff-resolver-redirect-uid-drop vpp-tun-hev-smoke hev-socketpair-probe android-preflight android-hev-build android-socks5-smoke-server-build android-thread-affinity-probe android-vpp-worker-affinity-probe android-vpp-placement-matrix android-vpp-configure-probe android-vpp-build-probe android-vpp-build-nfqueue-plugin android-vpp-stage-core android-vpp-push-core android-vpp-version-probe android-vpp-minimal-probe android-vpp-configure-release android-vpp-build-release android-vpp-stage-release android-vpp-push-release android-vpp-minimal-release android-vpp-configure-release-no-multiarch android-vpp-build-release-no-multiarch android-vpp-stage-release-no-multiarch android-vpp-push-release-no-multiarch android-vpp-minimal-release-no-multiarch android-vpp-configure-release-no-multiarch-no-ipsec android-vpp-build-release-no-multiarch-no-ipsec android-vpp-stage-release-no-multiarch-no-ipsec android-vpp-push-release-no-multiarch-no-ipsec android-vpp-minimal-release-no-multiarch-no-ipsec android-vpp-configure-release-no-multiarch-no-ipsec-idle android-vpp-build-release-no-multiarch-no-ipsec-idle android-vpp-stage-release-no-multiarch-no-ipsec-idle android-vpp-push-release-no-multiarch-no-ipsec-idle android-vpp-minimal-release-no-multiarch-no-ipsec-idle android-vpp-configure-trim-nfqueue android-vpp-build-trim-nfqueue android-vpp-stage-trim-nfqueue android-vpp-push-trim-nfqueue android-vpp-minimal-trim-nfqueue android-vpp-build-lite android-vpp-stage-lite android-vpp-push-lite android-vpp-minimal-lite setup-netns cleanup-netns collect-cpu

IMAGE ?= sakamoto-vpp-nfq-poc:dev
ANDROID_RELEASE_BUILD_DIR ?= $(CURDIR)/work/vpp-android-release
ANDROID_RELEASE_STAGE_DIR ?= $(CURDIR)/work/android-vpp-release-stage
ANDROID_RELEASE_NOMARCH_BUILD_DIR ?= $(CURDIR)/work/vpp-android-release-no-multiarch
ANDROID_RELEASE_NOMARCH_STAGE_DIR ?= $(CURDIR)/work/android-vpp-release-no-multiarch-stage
ANDROID_RELEASE_NOMARCH_CMAKE_ARGS ?= -DVPP_MARCH_VARIANT_OCTEONTX2=OFF -DVPP_MARCH_VARIANT_THUNDERX2T99=OFF -DVPP_MARCH_VARIANT_CORTEXA72=OFF -DVPP_MARCH_VARIANT_NEOVERSEN1=OFF -DVPP_MARCH_VARIANT_NEOVERSEV2=OFF
ANDROID_RELEASE_NOIPSEC_BUILD_DIR ?= $(CURDIR)/work/vpp-android-release-no-multiarch-no-ipsec
ANDROID_RELEASE_NOIPSEC_STAGE_DIR ?= $(CURDIR)/work/android-vpp-release-no-multiarch-no-ipsec-stage
ANDROID_RELEASE_NOIPSEC_CMAKE_ARGS ?= $(ANDROID_RELEASE_NOMARCH_CMAKE_ARGS) -DSAKAMOTO_VPP_NO_IPSEC=ON
ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR ?= $(CURDIR)/work/vpp-android-release-no-multiarch-no-ipsec-idle
ANDROID_RELEASE_NOIPSEC_IDLE_STAGE_DIR ?= $(CURDIR)/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage
ANDROID_RELEASE_NOIPSEC_IDLE_CMAKE_ARGS ?= $(ANDROID_RELEASE_NOIPSEC_CMAKE_ARGS) -DSAKAMOTO_VPP_ANDROID_IDLE_PROFILE=ON
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

smoke-ipv6-accept:
	IP_FAMILY=inet6 ./scripts/run-smoke.sh accept-all

smoke-ipv6-drop:
	IP_FAMILY=inet6 ./scripts/run-smoke.sh drop-all

smoke-ipv6-ratio:
	IP_FAMILY=inet6 ./scripts/run-smoke.sh drop-ratio=50

poc-rules-cli-check:
	./scripts/poc-rules-to-vppctl.py configs/rules-block-shell-uid.json --event-log /tmp/sakamoto-events.ndjson

android-package-rules-json:
	@./scripts/android-package-rules-json.sh "$(PACKAGE)"

android-list-user-packages-json:
	@./scripts/android-list-user-packages-json.sh

android-package-block-poc:
	@./scripts/android-run-package-block-poc.sh "$(PACKAGE)"

android-vpn-owner-uid-poc:
	@./scripts/android-run-vpn-owner-uid-poc.sh

android-vpn-owner-uid-ipv6-poc:
	@IP_FAMILY=inet6 ./scripts/android-run-vpn-owner-uid-poc.sh

android-vpn-owner-gate-poc:
	@./scripts/android-run-vpn-owner-gate-poc.sh

android-vpn-owner-gate-ipv6-poc:
	@IP_FAMILY=inet6 ./scripts/android-run-vpn-owner-gate-poc.sh

android-vpn-owner-gate-udp-poc:
	@./scripts/android-run-vpn-owner-gate-udp-poc.sh

android-vpn-owner-gate-udp-ipv6-poc:
	@IP_FAMILY=inet6 ./scripts/android-run-vpn-owner-gate-udp-poc.sh

android-vpp-hev-handoff-poc:
	@./scripts/android-run-vpp-hev-handoff-poc.sh

android-vpp-hev-handoff-ipv4-drop-poc:
	@BLOCK_IP4_DST=142.251.13.94 EXPECT_DROP=1 ./scripts/android-run-vpp-hev-handoff-poc.sh

android-vpp-hev-handoff-redirect-poc:
	@REDIRECT_THREAD=2 ./scripts/android-run-vpp-hev-handoff-poc.sh

android-vpp-owner-resolver-poc:
	@./scripts/android-run-vpp-owner-resolver-poc.sh

android-vpp-owner-resolver-cache-poc:
	@OWNER_CACHE=1 ./scripts/android-run-vpp-owner-resolver-poc.sh

android-vpp-owner-resolver-uid-drop-poc:
	@BLOCK_OWNER_UID=package EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-poc.sh

android-vpp-owner-resolver-ipv6-uid-drop-poc:
	@HOST=2606:4700:4700::1111 BLOCK_OWNER_UID=package ENABLE_IPV6=1 EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-poc.sh

android-vpp-owner-resolver-redirect-uid-drop-poc:
	@BLOCK_OWNER_UID=package REDIRECT_THREAD=2 EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-poc.sh

android-vpp-owner-resolver-ipv6-redirect-uid-drop-poc:
	@HOST=2606:4700:4700::1111 BLOCK_OWNER_UID=package REDIRECT_THREAD=2 ENABLE_IPV6=1 EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-poc.sh

android-vpp-owner-resolver-udp-drop-poc:
	@BLOCK_OWNER_UID=package EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-udp-poc.sh

android-vpp-owner-resolver-udp-redirect-drop-poc:
	@BLOCK_OWNER_UID=package REDIRECT_THREAD=2 EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-udp-poc.sh

android-vpp-owner-resolver-udp-cache-burst-poc:
	@UDP_COUNT=20 BLOCK_OWNER_UID=package OWNER_CACHE=1 EXPECT_DROP=1 EXPECT_MIN_UID_BLOCK_PACKETS=20 ./scripts/android-run-vpp-owner-resolver-udp-poc.sh

android-vpp-owner-resolver-ipv6-udp-drop-poc:
	@HOST=2606:4700:4700::1111 BLOCK_OWNER_UID=package ENABLE_IPV6=1 EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-udp-poc.sh

android-vpp-owner-resolver-ipv6-udp-redirect-drop-poc:
	@HOST=2606:4700:4700::1111 BLOCK_OWNER_UID=package REDIRECT_THREAD=2 ENABLE_IPV6=1 EXPECT_DROP=1 ./scripts/android-run-vpp-owner-resolver-udp-poc.sh

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

vpp-nfqueue-ipv6-accept:
	IP_FAMILY=inet6 ./scripts/run-vpp-nfqueue-smoke.sh accept-all

vpp-nfqueue-ipv6-drop:
	IP_FAMILY=inet6 ./scripts/run-vpp-nfqueue-smoke.sh drop-all

vpp-nfqueue-ipv6-ratio:
	IP_FAMILY=inet6 ./scripts/run-vpp-nfqueue-smoke.sh drop-ratio=50

vpp-nfqueue-ipv6-block-peer:
	IP_FAMILY=inet6 EXPECTED_VERDICT=drop ./scripts/run-vpp-nfqueue-smoke.sh block-ip6-dst=fd00:42::2

vpp-nfqueue-ipv6-block-miss:
	IP_FAMILY=inet6 EXPECTED_VERDICT=accept ./scripts/run-vpp-nfqueue-smoke.sh block-ip6-dst=fd00:42::99

vpp-nfqueue-ipv6-events:
	IP_FAMILY=inet6 EXPECTED_VERDICT=drop EXPECT_EVENTS=1 EVENT_LOG="$(CURDIR)/results/vpp-nfqueue-ipv6-events.ndjson" ./scripts/run-vpp-nfqueue-smoke.sh block-ip6-dst=fd00:42::2

vpp-nfqueue-idle-cpu:
	./scripts/run-vpp-nfqueue-idle-cpu.sh

vpp-tun-poc-build:
	./scripts/apply-vpp-overlay.sh
	TARGET=tun_poc_plugin ./scripts/build-vpp-plugin.sh

vpp-tun-poc-api-status-smoke:
	./scripts/run-vpp-tun-poc-api-status-smoke.py

vpp-tun-poc-smoke:
	./scripts/run-vpp-tun-poc-smoke.sh

vpp-tun-forward-fd-smoke:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-startup.conf" \
		--log-dir "$(CURDIR)/results"

vpp-tun-worker-thread-smoke:
	./scripts/run-vpp-tun-worker-thread-smoke.sh

vpp-tun-handoff-probe-smoke:
	./scripts/run-vpp-tun-handoff-probe-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results"

vpp-tun-handoff-forward-fd-smoke:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--tun-poc-mode handoff-forward-fd

vpp-tun-handoff-forward-fd-redirect-smoke:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--tun-poc-mode handoff-forward-fd \
		--target-thread 1 \
		--redirect-thread 2

vpp-tun-handoff-forward-fd-ipv4-drop:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--tun-poc-mode handoff-forward-fd \
		--block-ip4-dst 198.19.0.2 \
		--expect-drop

vpp-tun-handoff-forward-fd-ipv4-miss:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--tun-poc-mode handoff-forward-fd \
		--block-ip4-dst 198.19.0.99

vpp-tun-handoff-forward-fd-ipv6-drop:
	./scripts/run-vpp-tun-forward-fd-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--tun-poc-mode handoff-forward-fd \
		--ip-family inet6 \
		--addr fd00:42::1/64 \
		--remote-ip fd00:42::2 \
		--block-ip6-dst fd00:42::2 \
		--expect-drop

vpp-tun-handoff-tuple-smoke:
	./scripts/run-vpp-tun-handoff-tuple-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results"

vpp-tun-handoff-tuple-ipv6-smoke:
	./scripts/run-vpp-tun-handoff-tuple-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--ip-family inet6 \
		--addr fd00:43::1/64 \
		--local-ip fd00:43::1 \
		--remote-ip fd00:43::2

vpp-tun-handoff-resolver-smoke:
	./scripts/run-vpp-tun-handoff-resolver-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results"

vpp-tun-handoff-resolver-uid-drop:
	./scripts/run-vpp-tun-handoff-resolver-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--block-owner-uid 4242 \
		--expect-uid-drop

vpp-tun-handoff-resolver-redirect-uid-drop:
	./scripts/run-vpp-tun-handoff-resolver-smoke.py \
		--vpp-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vpp" \
		--vppctl-bin "$(CURDIR)/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl" \
		--vpp-config "$(CURDIR)/configs/tun-poc-workers-startup.conf" \
		--log-dir "$(CURDIR)/results" \
		--target-thread 1 \
		--redirect-thread 2 \
		--block-owner-uid 4242 \
		--expect-uid-drop

vpp-tun-hev-smoke:
	./scripts/run-vpp-tun-hev-smoke.sh

hev-socketpair-probe:
	./scripts/run-hev-socketpair-probe.sh

android-preflight:
	./scripts/android-preflight.sh

android-hev-build:
	./scripts/android-build-hev.sh

android-socks5-smoke-server-build:
	./scripts/android-build-socks5-smoke-server.sh

android-thread-affinity-probe:
	./scripts/android-run-thread-affinity-probe.sh

android-vpp-worker-affinity-probe:
	./scripts/android-run-vpp-worker-affinity-probe.sh

android-vpp-placement-matrix:
	./scripts/android-run-vpp-placement-matrix.sh

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

android-vpp-configure-release:
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" VPP_CMAKE_BUILD_TYPE=release VPP_PLUGINS="nfqueue_poc;tun_poc" ./scripts/android-configure-vpp-probe.sh

android-vpp-build-release:
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" TARGET=vppctl ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" TARGET=tun_poc_plugin ./scripts/android-build-vpp-probe.sh

android-vpp-stage-release:
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_STAGE_DIR)" ./scripts/android-stage-vpp-core.sh

android-vpp-push-release:
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_STAGE_DIR)" ./scripts/android-push-vpp-core.sh

android-vpp-minimal-release:
	BUILD_DIR="$(ANDROID_RELEASE_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_STAGE_DIR)" ./scripts/android-run-vpp-minimal.sh

android-vpp-configure-release-no-multiarch:
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" VPP_CMAKE_BUILD_TYPE=release VPP_PLUGINS="nfqueue_poc;tun_poc" VPP_EXTRA_CMAKE_ARGS="$(ANDROID_RELEASE_NOMARCH_CMAKE_ARGS)" ./scripts/android-configure-vpp-probe.sh

android-vpp-build-release-no-multiarch:
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" TARGET=vppctl ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" TARGET=tun_poc_plugin ./scripts/android-build-vpp-probe.sh

android-vpp-stage-release-no-multiarch:
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOMARCH_STAGE_DIR)" ./scripts/android-stage-vpp-core.sh

android-vpp-push-release-no-multiarch:
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOMARCH_STAGE_DIR)" ./scripts/android-push-vpp-core.sh

android-vpp-minimal-release-no-multiarch:
	BUILD_DIR="$(ANDROID_RELEASE_NOMARCH_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOMARCH_STAGE_DIR)" ./scripts/android-run-vpp-minimal.sh

android-vpp-configure-release-no-multiarch-no-ipsec:
	./scripts/apply-vpp-android-overlay.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" VPP_CMAKE_BUILD_TYPE=release VPP_PLUGINS="nfqueue_poc;tun_poc" VPP_EXTRA_CMAKE_ARGS="$(ANDROID_RELEASE_NOIPSEC_CMAKE_ARGS)" ./scripts/android-configure-vpp-probe.sh

android-vpp-build-release-no-multiarch-no-ipsec:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" TARGET=vppctl ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" TARGET=tun_poc_plugin ./scripts/android-build-vpp-probe.sh

android-vpp-stage-release-no-multiarch-no-ipsec:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOIPSEC_STAGE_DIR)" ./scripts/android-stage-vpp-core.sh

android-vpp-push-release-no-multiarch-no-ipsec:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOIPSEC_STAGE_DIR)" ./scripts/android-push-vpp-core.sh

android-vpp-minimal-release-no-multiarch-no-ipsec:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOIPSEC_STAGE_DIR)" ./scripts/android-run-vpp-minimal.sh

android-vpp-configure-release-no-multiarch-no-ipsec-idle:
	./scripts/apply-vpp-android-overlay.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" VPP_CMAKE_BUILD_TYPE=release VPP_PLUGINS="nfqueue_poc;tun_poc" VPP_EXTRA_CMAKE_ARGS="$(ANDROID_RELEASE_NOIPSEC_IDLE_CMAKE_ARGS)" ./scripts/android-configure-vpp-probe.sh

android-vpp-build-release-no-multiarch-no-ipsec-idle:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" TARGET=vppctl ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" TARGET=tun_poc_plugin ./scripts/android-build-vpp-probe.sh

android-vpp-stage-release-no-multiarch-no-ipsec-idle:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_STAGE_DIR)" ./scripts/android-stage-vpp-core.sh

android-vpp-push-release-no-multiarch-no-ipsec-idle:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_STAGE_DIR)" ./scripts/android-push-vpp-core.sh

android-vpp-minimal-release-no-multiarch-no-ipsec-idle:
	BUILD_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_BUILD_DIR)" STAGE_DIR="$(ANDROID_RELEASE_NOIPSEC_IDLE_STAGE_DIR)" ./scripts/android-run-vpp-minimal.sh

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
