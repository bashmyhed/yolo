# ULPF Makefile

.PHONY: all build test clean datasets demo benchmark

all: build

build:
	go build -o bin/ulpf ./cmd/ulpf

test:
	go test -v ./tests/unit/... ./tests/integration/...

test-failure:
	go test -v ./tests/failure/...

benchmark:
	go test -v ./tests/performance/...

clean:
	rm -rf bin/ data/ results/

datasets: dataset-synthetic

dataset-synthetic:
	go run scripts/gen_synthetic.go

demo:
	./bin/ulpf ingest --config configs/ulpf-demo.yaml

# Air-gap support
vendor:
	./scripts/vendor.sh

build-airgapped:
	./scripts/build-airgapped.sh

verify-offline:
	./scripts/verify-offline.sh
