.PHONY: build-smoke docker-build docker-shell fetch-vpp build-vpp smoke-accept smoke-drop smoke-ratio idle-cpu setup-netns cleanup-netns collect-cpu

IMAGE ?= sakamoto-vpp-nfq-poc:dev

build-smoke:
	./scripts/build-smoke.sh

docker-build:
	docker build -t $(IMAGE) .

docker-shell:
	./scripts/run-container.sh bash

fetch-vpp:
	./scripts/fetch-vpp.sh

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

collect-cpu:
	./scripts/collect-cpu.sh
