# Local entry points. `make safety` is fmt → clippy → nextest → ci-policy
# (the ci.yml `test` job). `make doc` is the sibling `doc` job, strict under
# RUSTDOCFLAGS=-D warnings. `make shellcheck` is the ci.yml `shellcheck` job
# (the binary if installed, else the koalaman/shellcheck:v0.11.0 image — the
# version ci.yml installs; the runner's package is 0.9.0). lld is required
# (see .cargo/config.toml).

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
KRB5_CONFIG ?= $(ROOT)/harness/nextest-krb5.conf
OUT ?=
GATE ?=
QUALITY ?=

.PHONY: safety fmt clippy test doc shellcheck policy harness stop-harness rust-kdc gate snapshot checkpoint budget

safety: fmt clippy test policy

fmt:
	cargo fmt --all -- --check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	KRB5_CONFIG=$(KRB5_CONFIG) cargo nextest run --workspace --profile ci --features krb5-kdc/test-hooks,krb5-admin/test-hooks

doc:
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

shellcheck:
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -S style scripts/*.sh scripts/lib/*.sh harness/*.sh harness/prod/*.sh dist/*.sh; \
	else \
	  docker run --rm -v "$(ROOT):/mnt:ro" koalaman/shellcheck:v0.11.0 -S style scripts/*.sh scripts/lib/*.sh harness/*.sh harness/prod/*.sh dist/*.sh; \
	fi

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

# The product as Fedora's krb5-server and krb5-workstation lay out MIT's (docs/install.md;
# dist/install.sh does the copying and keeps the manifest uninstall reads). `make build` is the
# release build with no features, so no test hooks: run it as yourself, then `sudo make install`,
# which never compiles, nor does any install goal run as root. KDCDIR is the programs'
# compiled-in KDC directory (KERBER_KDC_DIR at build time); it does not follow PREFIX.
PREFIX ?= /usr/local
DESTDIR ?=
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
DATADIR ?= $(PREFIX)/share
SYSCONFDIR ?= /etc
SYSCONFIGDIR ?= $(SYSCONFDIR)/sysconfig
LOGROTATEDIR ?= $(SYSCONFDIR)/logrotate.d
UNITDIR ?= $(PREFIX)/lib/systemd/system
TMPFILESDIR ?= $(PREFIX)/lib/tmpfiles.d
KDCDIR ?= $(or $(KERBER_KDC_DIR),/var/kerberos/krb5kdc)
CARGO ?= cargo
CARGO_TARGET_DIR ?= $(ROOT)/target
# One stamp per KDC directory, so a build for another directory is a new build.
BUILD_STAMP := $(CARGO_TARGET_DIR)/release/.make-build$(subst /,-,$(KDCDIR))
BUILD_INPUTS := $(ROOT)/Cargo.toml $(ROOT)/Cargo.lock $(ROOT)/rust-toolchain.toml \
	$(ROOT)/.cargo/config.toml $(shell find '$(ROOT)/crates' -name '*.rs' -o -name Cargo.toml)
INSTALLER = RELEASE='$(CARGO_TARGET_DIR)/release' DIST='$(ROOT)/dist' DESTDIR='$(DESTDIR)' \
	BINDIR='$(BINDIR)' SBINDIR='$(SBINDIR)' SYSCONFIGDIR='$(SYSCONFIGDIR)' \
	LOGROTATEDIR='$(LOGROTATEDIR)' UNITDIR='$(UNITDIR)' TMPFILESDIR='$(TMPFILESDIR)' \
	KDCDIR='$(KDCDIR)' MANIFEST='$(DATADIR)/kerber-rust/install-manifest' sh '$(ROOT)/dist/install.sh'

.PHONY: build install install-clients uninstall

build: $(BUILD_STAMP)

$(BUILD_STAMP): $(BUILD_INPUTS)
	@if [ -n "$${SUDO_USER-}" ]; then \
	  echo "make: the release build is missing or older than the sources: run 'make build' as $$SUDO_USER first (sudo does not compile)" >&2; \
	  exit 1; \
	fi
	@if [ "$$(id -u)" = 0 ] && [ -n "$(filter install install-clients,$(MAKECMDGOALS))" ]; then \
	  echo "make: the release build is missing or older than the sources: run 'make build' first (an install goal does not compile as root)" >&2; \
	  exit 1; \
	fi
	$(if $(filter-out /var/kerberos/krb5kdc,$(KDCDIR)),KERBER_KDC_DIR='$(KDCDIR)') $(CARGO) build --release --locked \
	  --target-dir '$(CARGO_TARGET_DIR)' -p krb5-kdc -p krb5-admin -p krb5-client
	@rm -f '$(CARGO_TARGET_DIR)'/release/.make-build-*
	@touch '$@'

install: $(BUILD_STAMP)
	@$(INSTALLER) install

install-clients: $(BUILD_STAMP)
	@$(INSTALLER) install-clients

uninstall:
	@$(INSTALLER) uninstall
