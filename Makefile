# ACRA — make targets (see docs/05-repo-layout-and-run.md)
# Real targets: build, test, fmt, vet. Cluster targets are stubs until M6.

CLUSTER ?= acra
IMAGES  := controller gate apiserver workload
KIND    ?= combinative   # drift kind for `make inject`

IMAGE   ?= acra:dev

.PHONY: build test fmt vet tidy generate run inject \
        kind-up docker-build install deploy up install-kyverno demo console kind-down

## --- real now ---
build: ## compile all cmds
	go build ./...

test: ## run unit tests
	go test ./...

fmt: ; go fmt ./...
vet:  ; go vet ./...
tidy: ; go mod tidy

generate: ## deepcopy + CRD manifests (needs controller-gen; wired with M3 operator)
	@echo "TODO(M3): controller-gen object + crd -> config/crd"

## --- local demo (no cluster) ---
run: ## run the apiserver locally, serving the console at http://localhost:8080
	go run ./cmd/apiserver

inject: ## inject a drift: make inject KIND=combinative|independence|epoch|authority
	go run ./cmd/workload inject-drift $(KIND)

## --- cluster lifecycle (M6) ---
kind-up: ## create the kind cluster (maps node:30080 -> host:8080)
	kind create cluster --name $(CLUSTER) --config config/kind/kind.yaml

docker-build: ## build the acra image and load it into the kind cluster
	docker build -t $(IMAGE) .
	kind load docker-image $(IMAGE) --name $(CLUSTER)

install: ## apply the AgentPolicy CRD
	kubectl apply -f config/crd/agentpolicy.yaml

deploy: ## deploy the apiserver + operator + OTel collector + the sample AgentPolicy
	kubectl apply -f config/otel/collector.yaml
	kubectl apply -f config/deploy/apiserver.yaml
	kubectl apply -f config/deploy/controller.yaml
	kubectl apply -f config/samples/agentpolicy.yaml
	kubectl -n acra-system rollout status deploy/acra-apiserver --timeout=120s
	kubectl -n acra-system rollout status deploy/acra-controller --timeout=120s

up: kind-up docker-build install deploy ## one-shot: cluster + image + CRD + deploy
	@echo "ACRA is up → open http://localhost:8080 ; then: make inject KIND=combinative"

install-kyverno: ## (optional) install Kyverno + the approved-set policy (needs network)
	kubectl apply -f https://github.com/kyverno/kyverno/releases/latest/download/install.yaml
	-kubectl -n kyverno wait --for=condition=Available deploy --all --timeout=300s
	kubectl apply -f config/kyverno/approved-set.yaml

console: ## print the console URL (kind maps it to the host)
	@echo "open http://localhost:8080"

demo: inject ## inject a combinative drift (alias for `make inject`)

kind-down: ; kind delete cluster --name $(CLUSTER)
