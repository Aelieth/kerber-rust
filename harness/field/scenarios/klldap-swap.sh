#!/usr/bin/env bash
# harness/field/scenarios/klldap-swap.sh --leg mit|rust: KLLDAP on host docker, as the hand records f-F3-mit
# (--leg mit: KLLDAP's image as it is, MIT krb5-server inside) and f-F3 (--leg rust: krb5-server swapped for the
# ref's build) ran it. Each leg: the image by KLLDAP's `make test` recipe; its live-KDC FFI lane (gate/kdc-sandbox.sh
# + cargo test -p lldap-kerberos -- --ignored) on the two MIT client libraries F3-MIT used; the image booted once
# for the observations; gate/run-gate.sh, all phases (phase 80 on the fixture as it is, whose pinned key_seed
# fails two lines on MIT too); phase 80 again on a copy with a fresh key_seed. The rust leg first builds the ref in
# AlmaLinux 10 (docs/install.md "Build", then make install DESTDIR), checks the staged programs (strings, glibc
# floor), applies F3's one Dockerfile hunk and migrates the fixture's KDC by docs/install.md "In a container"
# (the doc read from the ref's archive by heading, so a doc change is what runs). It compares with the MIT leg:
# this run's, else runs/mit-latest; with neither, each comparison is NOT-RUN, which fails. No lab VM.
# Inputs (field.env): FIELD_KLLDAP_REPO + FIELD_KLLDAP_PIN (`git archive` of the pin, never a copy of the working
# tree), FIELD_KLLDAP_FIXTURE, FIELD_LLDAP_CLI. Docker names start kerber-field-<run id>-<leg>; all are removed at
# the end (BuildKit's cache stays), and so is the leg's scratch. Run by run.sh (REC_DIR, TMPDIR, FIELD_RUN,
# FIELD_TREE_TAR, FIELD_SHA, FIELD_REF, FIELD_DEADLINE).
# vms:
# legs: mit rust
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LEG=${2:-}
case "${1:-} $LEG" in
    "--leg mit" | "--leg rust") ;;
    *) echo "usage: klldap-swap.sh --leg mit|rust" >&2; exit 1 ;;
esac
: "${FIELD_RUN:?run by run.sh}" "${FIELD_TREE_TAR:?run by run.sh}" "${FIELD_SHA:?run by run.sh}" "${FIELD_REF:?run by run.sh}"
# shellcheck source=../lib/rec.sh
. "$HERE/../lib/rec.sh"
q() { printf '%q' "$1"; }
DOCB=$FIELD_LIB/docblocks.py
REPO=${FIELD_KLLDAP_REPO:-} PIN=${FIELD_KLLDAP_PIN:-} FIX=${FIELD_KLLDAP_FIXTURE:-} CLI=${FIELD_LLDAP_CLI:-}
ID=$(basename "$FIELD_RUN" | tr '[:upper:]' '[:lower:]')
N=kerber-field-$ID-$LEG          # this leg's images ($N:<what>), containers, volumes and network
T=$TMPDIR                        # the leg's tmp, under the run's directory: the same path on the host
SRC=$T/klldap CO=kerber-rust-${FIELD_SHA:0:12}
CACHE=$T/cache                   # rustup + cargo homes, one per lane environment
BASEDN=dc=testlabby,dc=local     # the fixture's base DN (f-F3-mit record, step 2b)
DK="nice -n 10 docker"           # the CLI niced; the builds and lanes run niced inside, capped at $CPUS CPUs
CPUS=8
export BUILDX_BUILDER=default    # the docker driver: the current buildx builder may not load images (f-F3-mit)
HX=''                            # the gate runs where jq is (lldap-cli needs it): here, or on the host
if ! command -v jq > /dev/null && command -v distrobox-host-exec > /dev/null; then HX=distrobox-host-exec; fi
KEYSEED_FAILS='[FAIL] 80-migration-boot: force-reset boot failed for another reason (see force-reset.log)
[FAIL] 80-migration-boot: admin login failed on the migrated database'
# Masked when the legs' gate tables are compared: the docker bridge address, and the two LLDAP audit-log row counts
# the gate reads from a copy of the live SQLite file (timing: f-F3-mit's run had 3 policy_change rows, a rerun 4).
NORM='s/172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+/<docker bridge address>/g; s/(policy_change rows recorded) \([0-9]+\)/\1 (<rows>)/; s/(logs rows survive the restart) \([0-9]+ → [0-9]+\)/\1 (<rows> → <rows>)/'

# On any exit: this leg's containers, network and volumes removed; its scratch deleted, with a container for
# what root wrote there (sources, toolchains, cargo targets, fixture copies: GBs, which run.sh's whole-run secret
# scan would otherwise read until its time limit); this leg's image tags removed.
cleanup() {
    local d=(timeout -k 5 300 docker) img
    {
        "${d[@]}" ps -aq --filter "name=$N-" | xargs -r "${d[@]}" rm -f
        "${d[@]}" network ls -q --filter "name=$N-" | xargs -r "${d[@]}" network rm
        "${d[@]}" volume ls -q --filter "name=$N-" | xargs -r "${d[@]}" volume rm
        img=$("${d[@]}" images -q "$N" | head -n 1)
        if [ -n "$img" ]; then
            # shellcheck disable=SC2016 # $0 is the container shell's: the leg's tmp
            "${d[@]}" run --rm --network none --user 0 -v "$T:$T" --entrypoint sh "$img" -c 'rm -rf "$0"/* "$0"/.[!.]*' "$T"
        fi
        rm -rf "${T:?}"/* "${T:?}"/.[!.]*
        "${d[@]}" images --format '{{.Repository}}:{{.Tag}}' "$N" | xargs -r "${d[@]}" rmi
    } > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# The leg's helper: per-leg secrets, the fresh key_seed, F3's Dockerfile hunk, the listening sockets.
cat > "$T/klldap-swap.py" <<'EOF'
import difflib, ipaddress, os, re, secrets, shutil, sys
cmd, args = sys.argv[1], sys.argv[2:]
if cmd == "secrets":  # <tmp> <fixture>: this leg's values (never printed), and what the leg's scan looks for
    t, fix = args
    vals = {k: secrets.token_hex(n) for k, n in (("FIXTURE_ADMIN_PASS", 16), ("FRESH_KEY_SEED", 32),
            ("LLDAP_JWT_SECRET", 32), ("LLDAP_KEY_SEED", 32), ("LLDAP_LDAP_USER_PASS", 16))}
    for d in ("secrets", "scan/secrets"):
        os.makedirs(os.path.join(t, d), mode=0o700, exist_ok=True)
    def put(p, s):
        with open(os.path.join(t, p), "w") as f:
            f.write(s)
    put("secrets/fixture-admin.password", vals["FIXTURE_ADMIN_PASS"] + "\n")
    put("secrets/freshkey.key-seed", vals["FRESH_KEY_SEED"] + "\n")
    put("secrets/boot.env", "".join("%s=%s\n" % (k, v) for k, v in vals.items() if k.startswith("LLDAP_"))
        + "LLDAP_LDAP_BASE_DN=dc=gate,dc=test\nLLDAP_DATABASE_URL=sqlite:////data/users.db?mode=rwc\n")
    m = re.search(r'(?m)^key_seed\s*=\s*"([^"]+)"', open(os.path.join(fix, "data/lldap_config.toml")).read())
    put("scan/secrets/run.env", "".join("%s=%s\n" % kv for kv in vals.items())
        + ("FIXTURE_KEY_SEED=%s\n" % m.group(1) if m else ""))
    shutil.copyfile(os.path.join(fix, "data/kadm5.keytab"), os.path.join(t, "scan/secrets/fixture-kadm5.keytab"))
    print("this leg's values: %s; the leg's scan also looks for the fixture's key_seed (%s) and its admin keytab's"
          " keys" % (", ".join(vals), "found" if m else "none"))
elif cmd == "keyseed":  # <lldap_config.toml> <file holding the fresh value>
    seed = open(args[1]).read().strip()
    text, n = re.subn(r'(?m)^key_seed\s*=.*$', 'key_seed = "%s"' % seed, open(args[0]).read())
    if n != 1:
        sys.exit("%s: %d key_seed lines, not one" % (args[0], n))
    open(args[0], "w").write(text)
    print("key_seed replaced by a fresh value; the rest of the copy is the fixture's")
elif cmd == "hunk":  # <Dockerfile> <out>: f-F3's one hunk (build/Dockerfile.diff); its context must occur once
    old = ("RUN microdnf install -y --assumeyes \\\n    tzdata bash openssl cyrus-sasl-gssapi krb5-server krb5-libs"
           " krb5-workstation openldap-clients procps-ng ca-certificates \\\n    && microdnf clean all\n")
    new = old.replace("krb5-server ", "") + (
        "\n# kerber-rust in place of krb5-server (f-F3's hunk): the ref's `make install DESTDIR=<staging> PREFIX=/usr`,\n"
        "# built on AlmaLinux 10 (--build-context kerber-rust=<staging>). COPY gives the image's existing /usr/sbin\n"
        "# and /usr/lib the staging's 0755, so they get their 0555 back.\n"
        "COPY --from=kerber-rust / /\nRUN chmod 0555 /usr/sbin /usr/lib\n")
    text = open(args[0]).read()
    if text.count(old) != 1:
        sys.exit("the Dockerfile holds the hunk's context %d times, not once" % text.count(old))
    open(args[1], "w").write(text.replace(old, new))
    sys.stdout.writelines(difflib.unified_diff(text.splitlines(True), text.replace(old, new).splitlines(True),
                                               "a/Dockerfile", "b/Dockerfile"))
elif cmd == "sockets":  # stdin "<proto> <hex addr:port> <state>" from /proc/net: the KDC's and kadmind's listeners,
    seen = set()       # as port/proto, @address when not the wildcard (0.0.0.0, [::]): short enough for checks.tsv
    for line in sys.stdin:
        proto, local, st = line.split()[:3]
        addr, port = local.split(":")
        if int(port, 16) in (88, 464, 749, 750) and st == ("0A" if proto.startswith("tcp") else "07"):
            raw = bytes.fromhex(addr)
            a = str(ipaddress.IPv4Address(raw[::-1])) if len(raw) == 4 else "[%s]" % ipaddress.IPv6Address(
                b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
            seen.add((int(port, 16), proto, "" if a in ("0.0.0.0", "[::]") else "@" + a))
    print("sockets: %s (on the wildcard unless @)" % " ".join("%d/%s%s" % s for s in sorted(seen)))
EOF
PY="python3 -B $(q "$T/klldap-swap.py")"

# logged <name> <ERE> <command>: the command with its whole output, redacted, in logs/<name>.log; prints the lines
# the ERE matches and the last three; exits with the command's status.
logged() {
    local log=$REC_DIR/logs/$1.log
    mkdir -p "$REC_DIR/logs"
    # shellcheck disable=SC2016 # $? and $rc are the generated command's own
    printf 'set -o pipefail; { %s; } 2>&1 | python3 -B %s > %s; rc=$?; grep -E -- %s %s; echo "--- logs/%s.log ends:"; tail -n 3 %s; exit $rc' \
        "$3" "$(q "$FIELD_LIB/redact.py")" "$(q "$log")" "$(q "$2")" "$(q "$log")" "$1" "$(q "$log")"
}
# image <tag> [Dockerfile] [build options]: KLLDAP's `make test` recipe (its Makefile, test:) under this leg's tag.
image() {
    check "image.$1" rc host "$(logged "image-$1" 'load metadata for|naming to|ERROR' "cd $(q "$SRC") && $DK build --progress=plain --file $(q "${2:-Dockerfile}") --build-arg VERSION=$VER-test --build-arg CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-cpu=native' --build-arg CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-cpu=native' ${3:-} --tag $N:$1 .")"
    check "image.$1.app" '  /app/kerberos_manager$' host "docker run --rm --network none --entrypoint sha256sum $N:$1 /app/lldap /app/kerberos_manager"
}
# ffienv <env> [swap]: the lane's "host" image $N:ffi-<env>[-swap] (F3-MIT's harness/ffi-<env>/Dockerfile); swap:
# F3's, krb5-server out and the staging in (Fedora 43's /usr/sbin is /usr/bin).
ffienv() {
    local s=${2:+-$2} f
    f=$T/ffi-$1$s.Dockerfile
    case $1$s in
        f43) printf 'FROM registry.fedoraproject.org/fedora:43\nRUN dnf install -y --setopt=install_weak_deps=False krb5-server krb5-workstation krb5-devel krb5-libs clang pkgconf-pkg-config gcc make python3 rustup procps-ng iproute && dnf clean all\n' > "$f" ;;
        alma10) printf 'FROM quay.io/almalinuxorg/10-minimal\nRUN microdnf install -y --assumeyes krb5-server krb5-workstation krb5-devel krb5-libs clang llvm gcc make pkgconf python3 procps-ng shadow-utils openssl-devel tar gzip findutils which && microdnf clean all\n' > "$f" ;;
        f43-swap) printf 'FROM %s\nRUN rpm -e krb5-server && ! rpm -q krb5-server\nCOPY --from=kerber-rust usr/sbin/ /usr/bin/\nRUN chmod 0555 /usr/bin\n' "$N:ffi-f43" > "$f" ;;
        alma10-swap) printf 'FROM %s\nRUN rpm -e krb5-server && ! rpm -q krb5-server\nCOPY --from=kerber-rust / /\nRUN chmod 0555 /usr/sbin /usr/lib\n' "$N:ffi-alma10" > "$f" ;;
    esac
    [ -n "$s" ] || printf 'RUN groupadd -g 1000 builder && useradd -u 1000 -g 1000 -d /home/builder -m builder\n' >> "$f"
    mkdir -p "$T/empty"
    check "ffi.$1.image${2:+.$2}" rc host "$(logged "ffi-$1$s" 'load metadata for|naming to|ERROR' "$DK build --progress=plain --file $(q "$f") ${2:+--build-context kerber-rust=$(q "$STAGE")} --tag $N:ffi-$1$s $(q "$T/empty")")"
}
# lane <env> <image>: the lane in <image> as uid 1000, F3-MIT's run-test-kdc.sh (capture form): the provenance of
# the programs it runs, the tests, the sandbox's admin/admin. Graded: rc 0 and live_kdc's tests all passed.
lane() {
    local e=$1 L=$T/lane-$1 C=$CACHE/$1
    mkdir -p "$L" "$C"
    check "ffi.$e.lane" '^test result: ok\. [1-9][0-9]* passed; 0 failed' host "$(logged "lane-$e" '^(== |test result: )' "$DK run --rm -i --name $N-lane-$e --user $(id -u):$(id -g) --cpus $CPUS -v $(q "$T"):$(q "$T") -v $(q "$C"):$(q "$C") -e L=$(q "$L") -e C=$(q "$C") -e S=$(q "$SRC") $2 nice -n 10 bash -s < $(q "$T/lane.sh")")"
    sed -nE "s/^test result: [A-Za-z]+\. ([0-9]+) passed; ([0-9]+) failed.*/$e \1 \2/p" "$LAST_OUT" | grep -v ' 0 0$' >> "$REC_DIR/ffi.counts"
    observelast "obs.ffi.$e.admin" 'Attributes:.*'
}
cat > "$T/lane.sh" <<'EOF'
set -uo pipefail
export HOME=$L/home TMPDIR=$L/tmp CARGO_TARGET_DIR=$L/target RUSTUP_HOME=$C/rustup CARGO_HOME=$C/cargo
export PATH=$CARGO_HOME/bin:$PATH
mkdir -p "$HOME" "$TMPDIR" "$L/sandbox"
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal \
        --no-modify-path > "$L/rustup.log" 2>&1 || { cat "$L/rustup.log"; exit 1; }
fi
cd "$S" && rustup toolchain install > "$L/toolchain.log" 2>&1 || { cat "$L/toolchain.log"; exit 1; }
echo "== $(. /etc/os-release && echo "$PRETTY_NAME"), uid $(id -u), $(rustc --version)"
echo "== client: $(klist -V 2>&1 | head -n 1); $(rpm -q krb5-server krb5-libs krb5-workstation libkadm5 | tr '\n' ' ')"
for n in kdb5_util kadmin.local krb5kdc kadmind /usr/sbin/kadmin.local; do
    p=$(command -v "$n")
    echo "== prog ${n##*/} $p $(sha256sum < "$p" | cut -c1-64) $(rpm -qf "$p" 2>&1 | head -n 1)"
done
gate/kdc-sandbox.sh bash -c 'cargo test -p lldap-kerberos -- --ignored --nocapture; rc=$?
    kadmin.local -q "getprinc admin/admin" > "$L/sandbox/getprinc-admin.txt" 2>&1; exit $rc'
rc=$?
echo "== sandbox admin/admin $(grep -m 1 '^Attributes:' "$L/sandbox/getprinc-admin.txt")"
echo "== lane rc=$rc"
exit $rc
EOF
# gate <name> <fixture data> <fixture KDC> [phases]: KLLDAP's gate/run-gate.sh, unchanged, on this leg's image,
# where jq is; each line timestamped into logs/gate-<name>.log; its results stay in the leg's tmp.
gate() {
    local w=$T/gate-$1.sh log=$REC_DIR/logs/gate-$1.log
    mkdir -p "$REC_DIR/logs" "$T/gate-tmp"
    # shellcheck disable=SC2016 # the wrapper's own $(cat ...) and ${PIPESTATUS[0]}, run where the gate runs
    {
        printf 'set -uo pipefail\ncd %q || exit 1\n' "$SRC"
        printf 'export TMPDIR=%q GATE_IMAGE=%q GATE_DB=sqlite GATE_RESULTS_DIR=%q GATE_LLDAP_CLI=%q\n' \
            "$T/gate-tmp" "$N:$LEG" "$T/gate-results" "$T/lldap-cli"
        printf 'export GATE_FIXTURE_DATA=%q GATE_FIXTURE_KDC=%q GATE_FIXTURE_BASE_DN=%q GATE_PHASES=%q\n' \
            "$2" "$3" "$BASEDN" "${4:-}"
        printf 'GATE_FIXTURE_ADMIN_PASS=$(cat %q)\nexport GATE_FIXTURE_ADMIN_PASS\n' "$T/secrets/fixture-admin.password"
        printf '%s\n' "gate/run-gate.sh 2>&1 | python3 -u -c 'import sys, time
for l in sys.stdin: print(\"%.3f %s\" % (time.time(), l), end=\"\", flush=True)'" 'exit "${PIPESTATUS[0]}"'
    } > "$w"
    check "gate.$1" 'rc=0|1' host "set -o pipefail; $HX bash $(q "$w") 2>&1 | python3 -B $(q "$FIELD_LIB/redact.py") > $(q "$log"); rc=\$?; grep -E '^[0-9.]+ (KLLDAP gate|Gate results|\[FAIL\]|\[SKIP\])' $(q "$log"); exit \$rc"
    RID=$(sed -nE 's/^[0-9.]+ KLLDAP gate: .* run=([0-9]+-[0-9]+-[0-9]+)$/\1/p' "$log" | head -n 1)
    check "gate.$1.left" '^left: 0 containers, 0 volumes, 0 networks$' host "[ -n '$RID' ] || { echo 'no gate run id in its log'; exit 1; }; printf 'left: %s containers, %s volumes, %s networks\n' \"\$(docker ps -aq --filter name=$RID | wc -l)\" \"\$(docker volume ls -q --filter name=$RID | wc -l)\" \"\$(docker network ls -q --filter name=$RID | wc -l)\""
}
# cmpref <name> <file>: this leg's <file> against the reference MIT leg's (docker bridge addresses masked).
cmpref() {
    if [ -z "$REF_DIR" ] || [ ! -f "$REF_DIR/$2" ]; then
        _checkrow "cmp.$1" FAIL "as the MIT leg's $2" - "NOT-RUN: no MIT leg's $2 to compare with (this run's or runs/mit-latest)"
        return
    fi
    check "cmp.$1" rc host "diff <(sed -E '$NORM' $(q "$REF_DIR/$2")) <(sed -E '$NORM' $(q "$REC_DIR/$2")) && echo 'identical to $REF_DIR/$2'"
}

section "klldap-swap --leg $LEG: KLLDAP ${PIN:-<no pin>} on host docker$([ "$LEG" = rust ] && echo ", krb5-server swapped for ref $FIELD_REF = $FIELD_SHA")"
section "1. the inputs: KLLDAP's pin (git archive), the phase-80 fixture, lldap-cli; docker; the gate's tools"
check input.pin '^commit [0-9a-f]{40}$' host "[ -n $(q "$REPO") ] && [ -n $(q "$PIN") ] && c=\$(git -C $(q "$REPO") --no-optional-locks rev-parse --verify --quiet $(q "$PIN^{commit}")) || { echo 'FIELD_KLLDAP_REPO / FIELD_KLLDAP_PIN (field.env) name no commit'; exit 1; }; echo \"commit \$c\"; git -C $(q "$REPO") --no-optional-locks log -1 --format='%ci %s' \$c"
check input.fixture '^realm: [A-Z0-9.-]+$' host "[ -n $(q "$FIX") ] && cd $(q "$FIX") && ls -A data krb5kdc && ls krb5kdc/.k5.* | sed 's|^krb5kdc/\.k5\.|realm: |'"
REALM=$(sed -n 's/^realm: //p' "$LAST_OUT" | head -n 1)
check input.lldap-cli rc host "install -m 0700 $(q "$CLI") $(q "$T/lldap-cli") && sha256sum $(q "$T/lldap-cli") || exit 1; git -C \"\$(dirname $(q "$CLI"))\" --no-optional-locks log -1 --format='lldap-cli %H %ci' 2>/dev/null || true"
check input.docker '^docker [0-9.]+ / [0-9.]+$' host "docker version --format 'docker {{.Client.Version}} / {{.Server.Version}}'"
check input.gate.host '^gate host: ' host "$HX bash -c 'for c in docker jq python3 curl column timeout ldapsearch ldapmodify ldapwhoami ldappasswd; do command -v \$c > /dev/null || { echo \"gate host: no \$c\"; exit 1; }; done; echo \"gate host: \$(uname -n), with every tool the gate and lldap-cli run\"'"
check input.secrets '^this leg.s values: ' host "$PY secrets $(q "$T") $(q "$FIX")"

section "2. the KLLDAP source: git archive of the pin into the leg's tmp (the checkout is only read)"
check src.archive '^files: [0-9]+, as the commit lists$' host "set -o pipefail; rm -rf $(q "$SRC") && mkdir -p $(q "$SRC") && (umask 022 && git -C $(q "$REPO") --no-optional-locks archive $(q "$PIN") | tar -x -C $(q "$SRC")) && a=\$(find $(q "$SRC") ! -type d | wc -l) && b=\$(git -C $(q "$REPO") --no-optional-locks ls-tree -r $(q "$PIN") | wc -l) && if [ \"\$a\" = \"\$b\" ]; then echo \"files: \$a, as the commit lists\"; else echo \"files: \$a, the commit lists \$b\"; exit 1; fi"
VER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/Cargo.toml" 2>/dev/null | head -n 1)

if [ "$LEG" = rust ]; then
    section "3. the ref built in AlmaLinux 10 (KLLDAP's base) as docs/install.md says, then make install DESTDIR"
    KR=$T/$CO STAGE=$T/stage BH=$T/home
    check kr.tree '^files: [1-9][0-9]*$' host "rm -rf $(q "$KR") && (umask 022 && tar -x -C $(q "$T") -f $(q "$FIELD_TREE_TAR")) && echo \"files: \$(find $(q "$KR") -type f | wc -l)\""
    tar -xOf "$FIELD_TREE_TAR" "$CO/docs/install.md" > "$STATE/install.md"
    printf 'FROM quay.io/almalinuxorg/10-minimal\nRUN microdnf install -y --assumeyes gcc make lld binutils && microdnf clean all\n' > "$T/buildenv.Dockerfile"
    check kr.buildenv rc host "$(logged buildenv 'load metadata for|naming to|ERROR' "$DK build --progress=plain --tag $N:buildenv - < $(q "$T/buildenv.Dockerfile")")"
    BRUN="$DK run --rm --name $N-build --user $(id -u):$(id -g) --cpus $CPUS -e HOME=$(q "$BH") -v $(q "$T"):$(q "$T") -w $(q "$KR") $N:buildenv nice -n 10"
    note "the doc's Prerequisites on AlmaLinux: gcc make lld from microdnf (the build env image); rustup from its installer with the doc's flags, as AlmaLinux has no rustup package"
    check kr.rustup rc host "mkdir -p $(q "$BH") && $BRUN bash -c 'set -o pipefail; cat /etc/almalinux-release; rpm -q glibc gcc make lld && curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal'"
    check doc.build.script rc host "python3 -B $(q "$DOCB") script $(q "$STATE/install.md") '## Build' 1 --drop '^git clone ' --drop '^cd kerber-rust\$' --session '. \"\$HOME/.cargo/env\"' --session 'cd $(q "$KR")' > $(q "$STATE/build.sh")"
    host "$BRUN bash $(q "$STATE/build.sh")"
    python3 -B "$DOCB" results "$LAST_OUT" > "$STATE/build.results" || _checkrow doc.build FAIL units "$LAST_RC" "no command of the block ran"
    while IFS=$'\t' read -r i rc nout first; do
        _checkrow "doc.build.$i" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" rc "$rc" "rc=$rc, $nout output lines: $first"
    done < "$STATE/build.results"
    check kr.install '^installed /usr/sbin/krb5kdc$' host "$BRUN bash -c 'umask 022 && . \"\$HOME/.cargo/env\" && make install DESTDIR=$(q "$STAGE") PREFIX=/usr && cd $(q "$STAGE") && find . -printf \"%M %U:%G %8s %p\\n\" | sort -k4'"
    awk '{ print $1 "  /stage" $2 }' "$STAGE/usr/share/kerber-rust/install-manifest" > "$T/stage.manifest" 2>/dev/null
    SRUN="docker run --rm -i --name $N-check --network none -v $(q "$STAGE"):/stage:ro -v $(q "$T/stage.manifest"):/stage.manifest:ro $N:buildenv"
    check strings.control rc host "$SRUN sh -s -- --control < $(q "$FIELD_LIB/strings-check.sh")"
    check strings.manifest '^programs in /stage.manifest: [1-9][0-9]*, all [1-9][0-9]* checked$' host "$SRUN sh -s -- --manifest /stage.manifest < $(q "$FIELD_LIB/strings-check.sh")"
    check kr.glibc '^GLIBC_[0-9.]+ /stage/' host "$SRUN sh -c 'for p in \$(awk \"{ print \\\$2 }\" /stage.manifest | grep -E \"/s?bin/\"); do printf \"%s %s\\n\" \"\$(objdump -T \$p | grep -oE \"GLIBC_[0-9.]+\" | sort -uV | tail -n 1)\" \$p; done'"
    FLOOR=$(sed -n 's/^GLIBC_\([0-9.]*\) .*/\1/p' "$LAST_OUT" | sort -uV | tail -n 1)

    section "4. the images: KLLDAP's own (MIT, for the dump), then F3's one hunk with the staging in krb5-server's place"
    image old
    check image.rust.hunk '^\+COPY --from=kerber-rust / /$' host "$PY hunk $(q "$SRC/Dockerfile") $(q "$T/swap.Dockerfile")"
    image rust "$T/swap.Dockerfile" "--build-context kerber-rust=$(q "$STAGE")"
    grep '  /app/' "$LAST_OUT" > "$REC_DIR/app.sha256"
    check image.rust.packages '^package krb5-server is not installed$' host "docker run --rm --network none --entrypoint sh $N:rust -c 'rpm -q glibc krb5-libs krb5-workstation libkadm5 && ! rpm -q krb5-server && klist -V'"
    observelast obs.image.krb5 'krb5-server-[^ ]+|package krb5-server is not installed'
    G=$(sed -n 's/^glibc-\([0-9.]*\)-.*/\1/p' "$LAST_OUT" | head -n 1)
    check glibc.floor '^glibc floor GLIBC_[0-9.]+, not above the image.s [0-9.]+$' host "[ -n '$FLOOR' ] && [ -n '$G' ] && [ \"\$(printf '%s\n' '$FLOOR' '$G' | sort -V | tail -n 1)\" = '$G' ] && echo \"glibc floor GLIBC_$FLOOR, not above the image's $G\" || { echo \"glibc floor GLIBC_${FLOOR:-?}, the image's ${G:-?}\"; exit 1; }"
    MODES="/ /usr /usr/sbin /usr/lib /usr/share /etc /var /var/kerberos /var/kerberos/krb5kdc /var/log/krb5 /app /data"
    check image.rust.modes rc host "diff <(docker run --rm --network none --entrypoint stat $N:old -c '%a %U:%G %n' $MODES) <(docker run --rm --network none --entrypoint stat $N:rust -c '%a %U:%G %n' $MODES) && echo 'modes and owners as in the MIT image:' && docker run --rm --network none --entrypoint stat $N:rust -c '%a %U:%G %n' $MODES"
    check image.rust.manifest '^manifest: [1-9][0-9]* files as staged$' host "docker run --rm --network none --entrypoint sh $N:rust -c 'sha256sum -c /usr/share/kerber-rust/install-manifest && echo \"manifest: \$(wc -l < /usr/share/kerber-rust/install-manifest) files as staged\"'"
else
    section "3. KLLDAP's image as it is, MIT krb5-server inside"
    image mit
    grep '  /app/' "$LAST_OUT" > "$REC_DIR/app.sha256"
    observe obs.image.krb5 'krb5-server-[^ ]+|package krb5-server is not installed' host "docker run --rm --network none --entrypoint sh $N:mit -c 'rpm -q glibc krb5-server krb5-libs krb5-workstation libkadm5; klist -V'"
fi

section "5. the FFI lane (gate/kdc-sandbox.sh + cargo test -p lldap-kerberos -- --ignored) on F3-MIT's two clients"
for e in alma10 f43; do
    ffienv "$e" ''
    if [ "$LEG" = rust ]; then
        ffienv "$e" swap
        lane "$e" "$N:ffi-$e-swap"
        check "ffi.$e.ours" '^ours: 5 of 5$' host "awk 'NR == FNR { m[\$2] = \$1; next } /^== prog / { n++; if (m[\"/usr/sbin/\" \$3] == \$5) k++ } END { printf \"ours: %d of %d\\n\", k, n; exit !(n == 5 && k == n) }' $(q "$STAGE/usr/share/kerber-rust/install-manifest") $(q "$REC_DIR/logs/lane-$e.log")"
    else
        lane "$e" "$N:ffi-$e"
    fi
done

KDC=$FIX/krb5kdc
if [ "$LEG" = rust ]; then
    section "6. the fixture's KDC migrated as docs/install.md 'In a container' says: the MIT image dumps, ours loads"
    KDC=$T/fixture-migrated/krb5kdc
    check migrate.copy rc host "rm -rf $(q "$T/fixture-migrated") && mkdir -p $(q "$T/fixture-migrated") && cp -a $(q "$FIX/krb5kdc") $(q "$KDC") && ls -lan $(q "$KDC")"
    check doc.migrate.blocks 'line:3' host "python3 -B $(q "$DOCB") count $(q "$STATE/install.md") '### In a container'"
    for b in 1 2 3; do
        case $b in
            1) opts="--set REALM=$(q "$REALM") --set VOLUME=$(q "$KDC") --set OLD_IMAGE=$N:old --set NEW_IMAGE=$N:rust" ;;
            2) opts="--drop '^docker stop '" ;;
            3) opts='' ;;
        esac
        check "doc.migrate-$b.script" rc host "python3 -B $(q "$DOCB") script $(q "$STATE/install.md") '### In a container' $b $opts > $(q "$STATE/migrate-$b.sh")"
    done
    note "the blocks run in one bash session, as a reader pastes them into one terminal: block 1's names and block 2's OWNER reach block 3; block 2's 'docker stop' is not run: no container runs the fixture's copy"
    host "cd $(q "$STATE") && . ./migrate-1.sh > migrate-1.out 2>&1; . ./migrate-2.sh > migrate-2.out 2>&1; . ./migrate-3.sh > migrate-3.out 2>&1; cat migrate-1.out migrate-2.out migrate-3.out"
    for b in 1 2 3; do
        python3 -B "$DOCB" results "$STATE/migrate-$b.out" > "$STATE/migrate-$b.results" || _checkrow "doc.migrate-$b" FAIL units - "no command of block $b ran"
        while IFS=$'\t' read -r i rc nout first; do
            _checkrow "doc.migrate-$b.$i" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" rc "$rc" "rc=$rc, $nout output lines: $first"
        done < "$STATE/migrate-$b.results"
    done
    check migrate.principals '^principals: [1-9][0-9]*, the dump.s$' host "a=\$(docker run --rm --network none --entrypoint /usr/sbin/kadmin.local -v $(q "$KDC"):/var/kerberos/krb5kdc $N:rust -r $(q "$REALM") -q listprincs | grep -E '^[^ ]+@[^ ]+\$' | sort) && b=\$(awk '\$1 == \"princ\" { print \$7 }' $(q "$KDC/mit-realm.dump") | sort) && [ -n \"\$a\" ] && [ \"\$a\" = \"\$b\" ] && echo \"principals: \$(printf '%s\n' \"\$a\" | wc -l), the dump's\" && printf '%s\n' \"\$a\" && ls -lan $(q "$KDC")"
fi

section "7. the image booted once, as the gate boots it (fresh volumes, no published port): the observations"
check boot.run rc host "docker network create $N-net && docker run -d --name $N-boot --network $N-net --env-file $(q "$T/secrets/boot.env") -v $N-boot-data:/data -v $N-boot-kdc:/var/kerberos/krb5kdc $N:$LEG"
check boot.healthy '^healthy, the KDC leg too, after [0-9]+ s$' host "for i in \$(seq 1 120); do if docker exec $N-boot /app/lldap healthcheck --config-file /data/lldap_config.toml --kerberos > /dev/null 2>&1 && docker exec $N-boot test -s /var/log/krb5/kadmind.log; then echo \"healthy, the KDC leg too, after \$i s\"; exit 0; fi; sleep 1; done; echo 'not healthy in 120 s'; exit 1"
observe obs.boot.sockets 'sockets: .*' host "set -o pipefail; docker exec $N-boot sh -c 'for f in tcp tcp6 udp udp6; do awk -v p=\$f \"NR > 1 { print p, \\\$2, \\\$4 }\" /proc/net/\$f; done' | $PY sockets"
observe obs.boot.logs 'logs: .*' host "docker exec $N-boot sh -c 'cd /var/log/krb5 && echo logs: \$(stat -c \"%n %a %u:%g\" kadmind.log krb5kdc.log); echo kdb: \$(ls -A /var/kerberos/krb5kdc)'"
observelast obs.boot.kdb 'kdb: .*'
observe obs.boot.json 'stdout JSON lines: [0-9]+' host "printf 'stdout JSON lines: %s\n' \"\$(docker logs $N-boot 2> /dev/null | grep -c '^{')\""
host "docker rm -f $N-boot && docker volume rm $N-boot-data $N-boot-kdc && docker network rm $N-net"

section "8. KLLDAP's gate, all phases (phase 80: the fixture's data as it is, its KDC $([ "$LEG" = rust ] && echo "as migrated" || echo "as it is"))"
gate all "$FIX/data" "$KDC"
sed -E 's/^[0-9]+\.[0-9]+ //' "$REC_DIR/logs/gate-all.log" | awk '/^=== phase: /{ p = 1 } p && !/^Logs: /' > "$REC_DIR/gate-table.txt"
check gate.table '^not PASS: the fixture.s two pinned key_seed lines, nothing else$' host "grep -E '^\[(FAIL|SKIP)\]' $(q "$REC_DIR/gate-table.txt") | diff - <(printf '%s\n' $(q "$KEYSEED_FAILS")) && echo \"not PASS: the fixture's two pinned key_seed lines, nothing else\"; grep '^Gate results: ' $(q "$REC_DIR/gate-table.txt")"
check gate.keyseed 'The private key has not changed' host "grep -h -m 1 'Error: ' $(q "$T/gate-results/$RID/80-migration-boot/force-reset.log")"

section "9. phase 80 on a copy of the fixture's data with a fresh key_seed (its precondition), the KDC as in step 8"
check phase80.copy '^key_seed replaced' host "rm -rf $(q "$T/fixture-freshkey") && mkdir -p $(q "$T/fixture-freshkey") && cp -a $(q "$FIX/data") $(q "$T/fixture-freshkey/data") && $PY keyseed $(q "$T/fixture-freshkey/data/lldap_config.toml") $(q "$T/secrets/freshkey.key-seed")"
gate phase80 "$T/fixture-freshkey/data" "$KDC" 80-migration
check phase80.result 'Gate results: 4 passed, 0 failed, 0 skipped$' host "grep -E 'Gate results: ' $(q "$REC_DIR/logs/gate-phase80.log")"

if [ "$LEG" = rust ]; then
    section "10. against the MIT leg: this run's, else runs/mit-latest (neither: each comparison NOT-RUN, a FAIL)"
    REF_DIR=''
    if [ -f "$FIELD_RUN/klldap-swap/mit/result" ]; then REF_DIR=$FIELD_RUN/klldap-swap/mit
    elif [ -d "$LAB_HOME/runs/mit-latest/klldap-swap/mit" ]; then REF_DIR=$LAB_HOME/runs/mit-latest/klldap-swap/mit; fi
    note "the MIT leg compared with: ${REF_DIR:-none}$([ -n "$REF_DIR" ] && echo " ($(cat "$REF_DIR/result" 2> /dev/null))")"
    cmpref app app.sha256
    cmpref ffi ffi.counts
    cmpref gate.table gate-table.txt
fi
check secrets.leg rc host "KERBER_LAB_HOME=$(q "$T/scan") FIELD_ADLAB_ENV=/dev/null python3 -B $(q "$FIELD_LIB/scan-secrets.py") $(q "$REC_DIR")"
finish
