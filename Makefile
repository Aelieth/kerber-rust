# Local entry points. `make safety` is fmt → clippy → nextest → ci-policy
# (the ci.yml `test` job). `make doc` is the sibling `doc` job, strict under
# RUSTDOCFLAGS=-D warnings. lld is required (see .cargo/config.toml).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
KRB5_CONFIG ?= $(ROOT)/harness/nextest-krb5.conf
OUT ?=
GATE ?=
QUALITY ?=

.PHONY: safety fmt clippy test doc policy harness stop-harness rust-kdc gate snapshot checkpoint budget

safety: fmt clippy test policy

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	KRB5_CONFIG=$(KRB5_CONFIG) cargo nextest run --workspace --profile ci

doc:
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

policy:
	python3 scripts/ci-policy.py

harness:
	./scripts/run-harness.sh

stop-harness:
	./scripts/stop-harness.sh

rust-kdc:
	./scripts/run-rust-kdc.sh

gate:
	@if [ -z "$(GATE)" ]; then echo "usage: make gate GATE=client-gate"; exit 2; fi
	@g="$(GATE)"; g=$${g%.sh}; case "$$g" in *-gate) ;; *) g="$$g-gate" ;; esac; \
	  ./scripts/$$g.sh

snapshot:
	@if [ -z "$(OUT)" ]; then echo "usage: make snapshot OUT=dir [QUALITY=1]"; exit 2; fi
	./scripts/hygiene-snapshot.sh $(if $(QUALITY),--quality,) $(OUT)

checkpoint:
	@if [ -z "$(OUT)" ]; then echo "usage: make checkpoint OUT=dir"; exit 2; fi
	./scripts/checkpoint.sh --out $(OUT)

budget:
	python3 scripts/ci-status.py --budget-report -n 15 --jobs
	python3 scripts/ci-status.py --check-budget -n 5 --workflow ci
