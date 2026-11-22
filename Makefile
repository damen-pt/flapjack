# Build and run Flapjack. `make help` lists targets.

BIN      := bin
FLAPJACK := $(BIN)/flapjack
HEAD_BIN := $(BIN)/flapjack-linux-arm64
GO_FILES := $(shell find . -name '*.go' -not -path './bin/*') go.mod

# Lab shape; override on the command line: make lab-up RACKS=3 NODES=4
# LAYOUT=tentacles: head, a tentacle per rack, compute nodes, Slurm.
# LAYOUT=flat: head and nodes on one network (X86_BIOS, X86_SECURE).
LAYOUT     ?= tentacles
RACKS      ?= 2
NODES      ?= 2
X86_BIOS   ?= 0
X86_SECURE ?= 0
NODE_MEM   ?= 0
POWER_ON   ?= true
LAB_DIR    ?= $(HOME)/.flapjack/lab

# Homebrew's qemu and swtpm must be on PATH for the lab.
export PATH := /opt/homebrew/bin:$(PATH)

.PHONY: help build dist test test-race test-lab lab-up lab-down lab-status lab-ssh lab-restart lab-destroy clean

help: ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

build: $(FLAPJACK) $(HEAD_BIN) ## Build the host binary and the linux/arm64 head-node binary

$(FLAPJACK): $(GO_FILES)
	@mkdir -p $(BIN)
	go build -o $@ ./cmd/flapjack

$(HEAD_BIN): $(GO_FILES)
	@mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $@ ./cmd/flapjack

dist: ## Build static Linux binaries for head nodes: bin/flapjack-linux-{amd64,arm64}
	@mkdir -p $(BIN)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(BIN)/flapjack-linux-amd64 ./cmd/flapjack
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $(BIN)/flapjack-linux-arm64 ./cmd/flapjack

test: ## Run unit tests
	go test ./...

test-race: ## Run unit tests with the race detector
	go test -race ./...

test-lab: ## Run QEMU integration tests (boots real VMs)
	FLAPJACK_LAB_IT=1 go test -count=1 -run Integration -v ./internal/lab/

lab-up: build ## Start the lab (LAYOUT, RACKS, NODES, X86_BIOS, X86_SECURE, NODE_MEM, POWER_ON)
	$(FLAPJACK) lab up --dir $(LAB_DIR) --layout $(LAYOUT) --racks $(RACKS) --nodes $(NODES) \
		--x86-bios $(X86_BIOS) --x86-secure $(X86_SECURE) --node-mem $(NODE_MEM) --power-on=$(POWER_ON)

lab-down: ## Stop the lab, keeping VM state (NVRAM, TPMs, head disk)
	$(FLAPJACK) lab down --dir $(LAB_DIR)

lab-status: ## Show nodes, BMCs and the head node
	$(FLAPJACK) lab status --dir $(LAB_DIR)

lab-ssh: ## SSH to the head node
	$(FLAPJACK) lab ssh --dir $(LAB_DIR)

lab-restart: build ## Restart the lab on the latest build (head node picks up the new binary)
	-$(FLAPJACK) lab down --dir $(LAB_DIR)
	$(MAKE) lab-up

lab-destroy: ## Stop the lab and delete its state (downloads are kept)
	$(FLAPJACK) lab destroy --dir $(LAB_DIR)

clean: ## Remove build output
	rm -rf $(BIN)
