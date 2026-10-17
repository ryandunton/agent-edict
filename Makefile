.PHONY: all build build-windows build-linux build-darwin test clean compile-all bundle native-example deps builder

BIN_DIR := bin
DIST_DIR := dist
PROFILES_DIR := profiles

deps:
	go mod download
	go mod verify

all: test build-windows

build: build-windows build-linux build-darwin

build-windows:
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/edict.exe ./cmd/edict
	@echo "Built $(BIN_DIR)/edict.exe"

build-linux:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/edict-linux ./cmd/edict
	@echo "Built $(BIN_DIR)/edict-linux"

build-darwin:
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BIN_DIR)/edict-darwin-arm64 ./cmd/edict
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BIN_DIR)/edict-darwin-amd64 ./cmd/edict
	@echo "Built $(BIN_DIR)/edict-darwin-arm64 and $(BIN_DIR)/edict-darwin-amd64"

test:
	go test -v ./...

compile-all:
	go run ./cmd/edict compile --profiles-dir $(PROFILES_DIR) --target-os all --output-dir $(DIST_DIR)/profiles

bundle: compile-all
	@mkdir -p $(DIST_DIR)
	cp policy-map.yaml $(DIST_DIR)/
	go run ./cmd/edict validate-bundle -dir $(DIST_DIR) -target-os all
	tar -czf $(DIST_DIR)/policy-bundle.tar.gz -C $(DIST_DIR) profiles policy-map.yaml
	@echo "Created $(DIST_DIR)/policy-bundle.tar.gz"

# Explicit, separate native example; does not relax the unified sample policy.
native-example:
	go run ./cmd/edict compile-native -profile examples/native/local-guardrails.yaml -target-os all -output-dir $(DIST_DIR)/native-example/profiles
	cp examples/native/policy-map.yaml $(DIST_DIR)/native-example/policy-map.yaml
	go run ./cmd/edict validate-bundle -dir $(DIST_DIR)/native-example -target-os all

builder: ## Build the configuration builder's WebAssembly into public/builder/
	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o public/builder/edict.wasm ./cmd/edict-wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" public/builder/wasm_exec.js
	gzip -9 -k -f public/builder/edict.wasm

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
