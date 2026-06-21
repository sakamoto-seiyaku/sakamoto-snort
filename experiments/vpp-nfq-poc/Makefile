.PHONY: build-smoke docker-build docker-shell fetch-vpp apply-vpp-overlay build-vpp smoke-accept smoke-drop smoke-ratio idle-cpu vpp-idle-cpu vpp-nfqueue-cli-check vpp-nfqueue-accept vpp-nfqueue-drop vpp-nfqueue-ratio vpp-nfqueue-idle-cpu setup-netns cleanup-netns collect-cpu

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

collect-cpu:
	./scripts/collect-cpu.sh
