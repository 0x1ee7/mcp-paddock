.PHONY: build test run demo up down

build:
	go build -o bin/ ./cmd/...

test:
	go test -race -count=1 ./...

# Run everything locally without Docker: tool server, gateway, then the demo.
run: build
	@./bin/opstools -listen 127.0.0.1:8081 > opstools.log 2>&1 & echo $$! > .opstools.pid
	@./bin/gateway -config config/policy.yaml -listen 127.0.0.1:8080 > audit.log 2>&1 & echo $$! > .gateway.pid
	@sleep 1
	@./bin/demo -gateway http://127.0.0.1:8080; \
	  kill $$(cat .opstools.pid) $$(cat .gateway.pid); rm -f .opstools.pid .gateway.pid; \
	  echo; echo "Gateway audit log: audit.log ($$(grep -c mcp_request audit.log) events, $$(grep -c '"decision":"deny"' audit.log) denied, $$(grep -c rate_limited audit.log) rate limited)"

# Full stack with Grafana, Tempo, Loki and Prometheus.
up:
	docker compose up -d --build
	@echo "Grafana: http://localhost:3000   Gateway: http://localhost:8080/mcp/ops"

demo:
	docker compose run --rm demo

down:
	docker compose down
