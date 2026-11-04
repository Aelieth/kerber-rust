#!/usr/bin/env bash
# harness/field/scenarios/klldap-swap.sh --leg mit|rust: KLLDAP on the klldap VM's docker (F4g; it ran on
# alien's docker before). As the hand records f-F3-mit (--leg mit: KLLDAP's image as it is, MIT krb5-server
# inside) and f-F3 (--leg rust: krb5-server swapped for the ref's build) ran it. Each leg, every docker step
# on the VM through `run klldap`: the image by KLLDAP's `make test` recipe; its live-KDC FFI lane
# (gate/kdc-sandbox.sh + cargo test -p lldap-kerberos -- --ignored) on the two MIT client libraries F3-MIT
# used; the image booted once for the observations; gate/run-gate.sh, all phases (phase 80 on the fixture as
# it is, whose pinned key_seed fails two lines on MIT too); phase 80 again on a copy with a fresh key_seed. The
# rust leg first builds the ref in an AlmaLinux 10 container on the VM (docs/install.md "Build", then make
# install DESTDIR), checks the staged programs (strings, glibc floor), applies F3's one Dockerfile hunk and
# migrates the fixture's KDC by docs/install.md "In a container". It compares with the MIT leg: this run's,
# else runs/mit-latest; with neither, or with an empty file on either side, each comparison fails.
# Nothing builds or runs in alien's docker: the inputs are pushed to the VM over the lab key, every docker
# command runs through `run klldap`, and a postflight asserts alien's `docker ps -a` and image digests are
# unchanged. The VM keeps the run's scratch under /var/tmp/kf-<id>-<leg> (removed at the end) and a persistent
# cargo cache under /var/tmp/kf-cache; the leg's VM containers, volumes, network and image tags are removed too.
# Inputs (field.env): FIELD_KLLDAP_REPO + FIELD_KLLDAP_PIN (`git archive` of the pin, never the working tree),
# FIELD_KLLDAP_FIXTURE, FIELD_LLDAP_CLI. Run by run.sh (REC_DIR, TMPDIR, FIELD_RUN, FIELD_TREE_TAR, FIELD_SHA,
# FIELD_REF, FIELD_DEADLINE).
# vms: klldap
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
N=kerber-field-$ID-$LEG          # this leg's images ($N:<what>), containers, volumes and network, on the klldap VM
T=$TMPDIR                        # alien's run scratch: the records, and the inputs generated here before being pushed
VT=/var/tmp/kf-$ID-$LEG          # this leg's scratch on the klldap VM: the source, the staging, docker volumes, gate results
VCACHE=/var/tmp/kf-cache         # rustup + cargo homes on the VM, kept across runs
VTS=$VT-secrets                  # this leg's injected secrets: a sibling dir OUTSIDE the mounted VT (boot --env-file, the gate's admin password)
SRC=$VT/klldap CO=kerber-rust-${FIELD_SHA:0:12}
BASEDN=dc=testlabby,dc=local     # the fixture's base DN (f-F3-mit record, step 2b)
VM=klldap                        # the Docker-host VM (192.168.177.30); every docker command runs here
DK="nice -n 10 docker"           # the CLI niced; the builds and lanes run niced inside, capped at $CPUS CPUs
CPUS=4                           # the klldap VM's vCPUs
KEYSEED_FAILS='[FAIL] 80-migration-boot: force-reset boot failed for another reason (see force-reset.log)
[FAIL] 80-migration-boot: admin login failed on the migrated database'
# Masked when the legs' gate tables are compared: the docker bridge address, and the two LLDAP audit-log row counts
# the gate reads from a copy of the live SQLite file (timing: f-F3-mit's run had 3 policy_change rows, a rerun 4).
NORM='s/172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+/<docker bridge address>/g; s/(policy_change rows recorded) \([0-9]+\)/\1 (<rows>)/; s/(logs rows survive the restart) \([0-9]+ → [0-9]+\)/\1 (<rows> → <rows>)/'

# vrun <name> <ERE|rc> <cmd>: run <cmd> on the VM, record it, and keep its whole (redacted) output in
# logs/<name>.log for the gate-table and compare steps; graded like `check` on $LAST_OUT.
vrun() {
    local name=$1 expect=$2 cmd=$3
    mkdir -p "$REC_DIR/logs"
    run "$VM" "$cmd"
    cp "$LAST_OUT" "$REC_DIR/logs/$name.log"
    checklast "$name" "$expect"
}
# vpush <what> <local file>: pipe a local file to the VM on stdin; the remote command places it. hostin records.
vpush() { local what=$1 lf=$2 rcmd=$3; hostin "$what" "$LABQ ssh $VM -- $(q "$rcmd")" < "$lf"; }
# aliendocker: alien's docker as a stable projection -- images by repo:tag/id/digest, containers by
# id/name/image/created time, sorted. Read-only (ps, images); the run never builds or runs a container here.
aliendocker() {
    { docker image ls --digests --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Digest}}'
      docker ps -a --format '{{.ID}} {{.Names}} {{.Image}} {{.CreatedAt}}'; } 2>/dev/null | LC_ALL=C sort
}

# On any exit: this leg's containers, network, volumes and image tags on the VM, and its VM scratch (VT),
# removed (VCACHE is kept). Nothing on alien's docker is touched.
cleanup() {
    timeout -k 5 300 "$LAB" ssh "$VM" -- "docker ps -aq --filter name=$N- | xargs -r docker rm -f; docker network ls -q --filter name=$N- | xargs -r docker network rm; docker volume ls -q --filter name=$N- | xargs -r docker volume rm; docker images --format '{{.Repository}}:{{.Tag}}' $N | xargs -r docker rmi; sudo rm -rf $(q "$VT") $(q "$VTS")" < /dev/null > /dev/null 2>&1
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# The leg's helper (generated on alien; pushed to the VM for keyseed/hunk/sockets, run on alien for secrets):
# per-leg secrets, the fresh key_seed, F3's Dockerfile hunk, the listening sockets.
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
PY_VM="python3 -B $VT/klldap-swap.py"            # the helper on the VM (keyseed, hunk, sockets)

# A cold KLLDAP image build ran past 900 s; this step allows 3600 s.
# run.sh reads the next line as this scenario's wall clock.
# field-limit scenario=5400
IMAGE_CMD_LIMIT=3600
# image <tag> [Dockerfile] [build options]: KLLDAP's `make test` recipe (its Makefile, test:) under this leg's tag, on the VM.
# app.sha256 is sha256sum of that image. The build log has no such line.
image() {
    local saved=$FIELD_CMD_TIMEOUT
    FIELD_CMD_TIMEOUT=$IMAGE_CMD_LIMIT
    vrun "image-$1" rc "cd $(q "$SRC") && export BUILDX_BUILDER=default && $DK build --progress=plain --file $(q "${2:-Dockerfile}") --build-arg VERSION=$VER-test --build-arg CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-cpu=native' --build-arg CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS='-C target-cpu=native' ${3:-} --tag $N:$1 . 2>&1"
    FIELD_CMD_TIMEOUT=$saved
    check "image.$1.app" '  /app/kerberos_manager$' run "$VM" "docker run --rm --network none --entrypoint sha256sum $N:$1 /app/lldap /app/kerberos_manager"
    if [ "$1" = "$LEG" ]; then
        grep '  /app/' "$LAST_OUT" > "$REC_DIR/app.sha256" || true
    fi
}
# Alma's mirrorlist can return gzip for repomd.xml, which microdnf will not parse. Use the repo file's own baseurl.
ALMA_SED='sed -i -e s/^mirrorlist=/#mirrorlist=/ -e s/^#\ baseurl=/baseurl=/ /etc/yum.repos.d/almalinux-baseos.repo /etc/yum.repos.d/almalinux-appstream.repo /etc/yum.repos.d/almalinux-extras.repo'
ALMA_PIN="$ALMA_SED && "
# ffienv <env> [swap]: the lane's "host" image $N:ffi-<env>[-swap] (F3-MIT's harness/ffi-<env>/Dockerfile) on the VM.
ffienv() {
    local s=${2:+-$2} f
    f=$VT/ffi-$1$s.Dockerfile
    case $1$s in
        f43) run "$VM" "printf 'FROM registry.fedoraproject.org/fedora:43\nRUN dnf install -y --setopt=install_weak_deps=False krb5-server krb5-workstation krb5-devel krb5-libs clang pkgconf-pkg-config gcc make python3 rustup procps-ng iproute && dnf clean all\n' > $(q "$f")" ;;
        alma10) run "$VM" "printf 'FROM quay.io/almalinuxorg/10-minimal\nRUN ${ALMA_PIN}microdnf install -y --assumeyes krb5-server krb5-workstation krb5-devel krb5-libs clang llvm gcc make pkgconf python3 procps-ng shadow-utils openssl-devel tar gzip findutils which && microdnf clean all\n' > $(q "$f")" ;;
        f43-swap) run "$VM" "printf 'FROM %s\nRUN rpm -e krb5-server && ! rpm -q krb5-server\nCOPY --from=kerber-rust usr/sbin/ /usr/bin/\nRUN chmod 0555 /usr/bin\n' $N:ffi-f43 > $(q "$f")" ;;
        alma10-swap) run "$VM" "printf 'FROM %s\nRUN rpm -e krb5-server && ! rpm -q krb5-server\nCOPY --from=kerber-rust / /\nRUN chmod 0555 /usr/sbin /usr/lib\n' $N:ffi-alma10 > $(q "$f")" ;;
    esac
    [ -n "$s" ] || run "$VM" "printf 'RUN groupadd -g 1000 builder && useradd -u 1000 -g 1000 -d /home/builder -m builder\n' >> $(q "$f")"
    run "$VM" "mkdir -p $(q "$VT/empty")"
    vrun "ffi-$1$s" rc "export BUILDX_BUILDER=default && $DK build --progress=plain --file $(q "$f") ${2:+--build-context kerber-rust=$(q "$STAGE")} --tag $N:ffi-$1$s $(q "$VT/empty") 2>&1"
}
# lane <env> <image>: the lane in <image> as uid 1000 on the VM, F3-MIT's run-test-kdc.sh (capture form).
lane() {
    local e=$1 L=$VT/lane-$1 C=$VCACHE/$1
    run "$VM" "mkdir -p $(q "$L") $(q "$C")"
    vrun "lane-$e" '^test result: ok\. [1-9][0-9]* passed; 0 failed' "$DK run --rm -i --name $N-lane-$e --user \$(id -u):\$(id -g) --cpus $CPUS -v $(q "$VT"):$(q "$VT") -v $(q "$VCACHE"):$(q "$VCACHE") -e L=$(q "$L") -e C=$(q "$C") -e S=$(q "$SRC") $2 nice -n 10 bash -s < $(q "$VT/lane.sh") 2>&1"
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
# gate <name> <fixture data> <fixture KDC> [phases]: KLLDAP's gate/run-gate.sh, unchanged, on this leg's image on the VM.
gate() {
    local w=$VT/gate-$1.sh log=$REC_DIR/logs/gate-$1.log
    mkdir -p "$REC_DIR/logs"
    # shellcheck disable=SC2016 # the wrapper's own $(cat ...) and ${PIPESTATUS[0]}, run on the VM where the gate runs
    {
        printf 'set -uo pipefail\ncd %q || exit 1\n' "$SRC"
        printf 'export TMPDIR=%q GATE_IMAGE=%q GATE_DB=sqlite GATE_RESULTS_DIR=%q GATE_LLDAP_CLI=%q\n' \
            "$VT/gate-tmp" "$N:$LEG" "$VT/gate-results" "$VT/lldap-cli"
        printf 'export GATE_FIXTURE_DATA=%q GATE_FIXTURE_KDC=%q GATE_FIXTURE_BASE_DN=%q GATE_PHASES=%q\n' \
            "$2" "$3" "$BASEDN" "${4:-}"
        printf 'GATE_FIXTURE_ADMIN_PASS=$(cat %q)\nexport GATE_FIXTURE_ADMIN_PASS\n' "$VTS/fixture-admin.password"
        printf '%s\n' "gate/run-gate.sh 2>&1 | python3 -u -c 'import sys, time
for l in sys.stdin: print(\"%.3f %s\" % (time.time(), l), end=\"\", flush=True)'" 'exit "${PIPESTATUS[0]}"'
    } > "$T/gate-$1.sh"
    vpush "gate-$1.sh" "$T/gate-$1.sh" "mkdir -p $VT/gate-tmp && cat > $w"
    vrun "gate-$1" 'rc=0|1' "bash $(q "$w")"
    grep -E '^[0-9.]+ (KLLDAP gate|Gate results|\[FAIL\]|\[SKIP\])' "$REC_DIR/logs/gate-$1.log" || true
    RID=$(sed -nE 's/^[0-9.]+ KLLDAP gate: .* run=([0-9]+-[0-9]+-[0-9]+)$/\1/p' "$log" | head -n 1)
    check "gate.$1.left" '^left: 0 containers, 0 volumes, 0 networks$' run "$VM" "[ -n '$RID' ] || { echo 'no gate run id in its log'; exit 1; }; docker version --format '{{.Server.Version}}' > /dev/null && printf 'left: %s containers, %s volumes, %s networks\n' \"\$(docker ps -aq --filter name=$RID | wc -l)\" \"\$(docker volume ls -q --filter name=$RID | wc -l)\" \"\$(docker network ls -q --filter name=$RID | wc -l)\""
}
# cmpref <name> <file>: this leg's <file> against the reference MIT leg's (docker bridge addresses masked). On alien.
# A missing or empty side fails and names that leg: diff would call two empty files identical.
cmpref() {
    local mitf='' mitlab="MIT $2"
    if [ -z "$REF_DIR" ]; then
        mitlab="MIT $2 (no MIT leg)"
    else
        mitf=$REF_DIR/$2
    fi
    sides "cmp.$1" "$mitlab" "$mitf" "rust $2" "$REC_DIR/$2" || return
    check "cmp.$1" rc host "diff <(sed -E '$NORM' $(q "$REF_DIR/$2")) <(sed -E '$NORM' $(q "$REC_DIR/$2")) && echo 'identical to $REF_DIR/$2'"
}

section "klldap-swap --leg $LEG: KLLDAP ${PIN:-<no pin>} on the klldap VM's docker$([ "$LEG" = rust ] && echo ", krb5-server swapped for ref $FIELD_REF = $FIELD_SHA")"
section "0. the VM: alien's docker state is recorded (read-only), the leg's stale artifacts are pre-cleaned, VT is made"
check alien.docker.before '^alien docker: [0-9]+ images, [0-9]+ containers$' host "printf 'alien docker: %s images, %s containers\n' \"\$(docker image ls -q | sort -u | wc -l)\" \"\$(docker ps -aq | wc -l)\""
aliendocker > "$T/alien-docker.before"
check vm.preclean '^pre-clean: done$' run "$VM" "docker version --format '{{.Server.Version}}' > /dev/null && docker ps -aq --filter name=$N- | xargs -r docker rm -f && docker network ls -q --filter name=$N- | xargs -r docker network rm && docker volume ls -q --filter name=$N- | xargs -r docker volume rm && docker images --format '{{.Repository}}:{{.Tag}}' $N | xargs -r docker rmi && sudo rm -rf $(q "$VT") $(q "$VTS") && mkdir -p $(q "$VT") $(q "$VCACHE") && mkdir -m 0700 -p $(q "$VTS") && echo 'pre-clean: done'"
# Under SELinux the VM's containers (container_t) cannot use tmp_t: VT and VCACHE get container_file_t, as -v's :z would
# give them, so the lanes, the build, the doc's blocks and the gate's own mounts (its phase 80 copies with cp -a, which
# keeps the label) can; what is made under them later takes it. Nothing else is relabelled, and VTS keeps tmp_t.
check vm.label '^labels: (container_file_t container_file_t|SELinux is off)$' run "$VM" "if selinuxenabled; then sudo chcon -R -t container_file_t $(q "$VT") $(q "$VCACHE") && echo \"labels: \$(stat -c %C $(q "$VT") | cut -d: -f3) \$(stat -c %C $(q "$VCACHE") | cut -d: -f3)\"; else echo 'labels: SELinux is off'; fi"
# the VM's docker inventory recorded for debugging (not a row: a count would differ between legs)
run "$VM" "docker ps -a --format '{{.Names}} {{.Image}}'; docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}'; docker volume ls -q; docker network ls --format '{{.Name}}'"

section "1. the inputs: KLLDAP's pin (git archive to the VM), the phase-80 fixture, lldap-cli; the VM's docker and gate tools"
check input.pin '^commit [0-9a-f]{40}$' host "[ -n $(q "$REPO") ] && [ -n $(q "$PIN") ] && c=\$(git -C $(q "$REPO") --no-optional-locks rev-parse --verify --quiet $(q "$PIN^{commit}")) || { echo 'FIELD_KLLDAP_REPO / FIELD_KLLDAP_PIN (field.env) name no commit'; exit 1; }; echo \"commit \$c\"; git -C $(q "$REPO") --no-optional-locks log -1 --format='%ci %s' \$c"
check input.fixture '^realm: [A-Z0-9.-]+$' host "[ -n $(q "$FIX") ] && cd $(q "$FIX") && ls -A data krb5kdc && ls krb5kdc/.k5.* | sed 's|^krb5kdc/\.k5\.|realm: |'"
REALM=$(sed -n 's/^realm: //p' "$LAST_OUT" | head -n 1)
check input.docker '^docker [0-9.]+ / [0-9.]+$' run "$VM" "docker version --format 'docker {{.Client.Version}} / {{.Server.Version}}' && docker buildx version"
check input.gate.host '^gate host: ' run "$VM" "for c in docker jq python3 curl column timeout ldapsearch ldapmodify ldapwhoami ldappasswd; do command -v \$c > /dev/null || { echo \"gate host: no \$c\"; exit 1; }; done; echo \"gate host: \$(uname -n), with every tool the gate and lldap-cli run\""
check input.secrets '^this leg.s values: ' host "python3 -B $(q "$T/klldap-swap.py") secrets $(q "$T") $(q "$FIX")"
vpush "klldap-swap.py" "$T/klldap-swap.py" "mkdir -p $VTS $VT/empty && cat > $VT/klldap-swap.py"
vpush "lane.sh" "$T/lane.sh" "cat > $VT/lane.sh"
vpush "boot.env" "$T/secrets/boot.env" "umask 077 && cat > $VTS/boot.env"
vpush "fixture-admin.password" "$T/secrets/fixture-admin.password" "umask 077 && cat > $VTS/fixture-admin.password"
check input.lldap-cli rc host "git -C \"\$(dirname $(q "$CLI"))\" --no-optional-locks log -1 --format='lldap-cli %H %ci' 2>/dev/null || true"
vpush "lldap-cli" "$CLI" "cat > $VT/lldap-cli && chmod 0700 $VT/lldap-cli"

section "2. the KLLDAP source: git archive of the pin to the VM (the checkout is only read)"
check src.archive '^files: [0-9]+, as the commit lists$' host "set -o pipefail; b=\$(git -C $(q "$REPO") --no-optional-locks ls-tree -r $(q "$PIN") | wc -l); (umask 022 && git -C $(q "$REPO") --no-optional-locks archive $(q "$PIN")) | $LABQ ssh $VM -- \"rm -rf $(q "$SRC") && mkdir -p $(q "$SRC") && tar -x -C $(q "$SRC") && a=\\\$(find $(q "$SRC") ! -type d | wc -l); if [ \\\"\\\$a\\\" = \$b ]; then echo \\\"files: \\\$a, as the commit lists\\\"; else echo \\\"files: \\\$a, the commit lists \$b\\\"; exit 1; fi\""
run "$VM" "sed -n 's/^version = \"\(.*\)\"/\1/p' $(q "$SRC/Cargo.toml") 2>/dev/null | head -n 1"
VER=$(grep -m1 . "$LAST_OUT" 2>/dev/null)
check src.alma-pin '^pinned the Dockerfile microdnf$' run "$VM" "python3 -c 'import pathlib,sys
p=pathlib.Path(sys.argv[1]); sed=sys.argv[2]
lines=p.read_text().splitlines(True); out=[]; done=False
for line in lines:
    if not done and line.startswith(\"RUN microdnf \"):
        out.append(\"RUN \"+sed+\"\\n\"); done=True
    out.append(line)
if not done: sys.exit(\"no RUN microdnf line\")
p.write_text(\"\".join(out)); print(\"pinned the Dockerfile microdnf\")' $(q "$SRC/Dockerfile") $(q "$ALMA_SED")"

if [ "$LEG" = rust ]; then
    section "3. the ref built in an AlmaLinux 10 container on the VM (KLLDAP's base) as docs/install.md says, then make install DESTDIR"
    KR=$VT/$CO STAGE=$VT/stage BH=$VT/home
    check kr.tree '^files: [1-9][0-9]*$' host "set -o pipefail; (umask 022 && cat $(q "$FIELD_TREE_TAR")) | $LABQ ssh $VM -- \"rm -rf $(q "$KR") && tar -x -C $(q "$VT") && echo \\\"files: \\\$(find $(q "$KR") -type f | wc -l)\\\"\""
    tar -xOf "$FIELD_TREE_TAR" "$CO/docs/install.md" > "$STATE/install.md"
    run "$VM" "printf 'FROM quay.io/almalinuxorg/10-minimal\nRUN ${ALMA_PIN}microdnf install -y --assumeyes gcc make lld binutils && microdnf clean all\n' > $(q "$VT/buildenv.Dockerfile")"
    vrun buildenv rc "export BUILDX_BUILDER=default && $DK build --progress=plain --tag $N:buildenv - < $(q "$VT/buildenv.Dockerfile") 2>&1"
    BRUN="$DK run --rm --name $N-build --user \$(id -u):\$(id -g) --cpus $CPUS -e HOME=$(q "$BH") -v $(q "$VT"):$(q "$VT") -w $(q "$KR") $N:buildenv nice -n 10"
    note "the doc's Prerequisites on AlmaLinux: gcc make lld from microdnf (the build env image); rustup from its installer with the doc's flags, as AlmaLinux has no rustup package"
    check kr.rustup rc run "$VM" "mkdir -p $(q "$BH") && $BRUN bash -c 'set -o pipefail; cat /etc/almalinux-release; rpm -q glibc gcc make lld && curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal'"
    check doc.build.script rc host "python3 -B $(q "$DOCB") script $(q "$STATE/install.md") '## Build' 1 --drop '^git clone ' --drop '^cd kerber-rust\$' --session '. \"\$HOME/.cargo/env\"' --session 'cd $(q "$KR")' > $(q "$STATE/build.sh")"
    vpush "build.sh" "$STATE/build.sh" "cat > $VT/build.sh"
    run "$VM" "$BRUN bash $(q "$VT/build.sh")"
    python3 -B "$DOCB" results "$LAST_OUT" > "$STATE/build.results" || _checkrow doc.build FAIL units "$LAST_RC" "no command of the block ran"
    while IFS=$'\t' read -r i rc nout first; do
        _checkrow "doc.build.$i" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" rc "$rc" "rc=$rc, $nout output lines: $first"
    done < "$STATE/build.results"
    check kr.install '^installed /usr/sbin/krb5kdc$' run "$VM" "$BRUN bash -c 'umask 022 && . \"\$HOME/.cargo/env\" && make install DESTDIR=$(q "$STAGE") PREFIX=/usr && cd $(q "$STAGE") && find . -printf \"%M %U:%G %8s %p\\n\" | sort -k4'"
    cp "$LAST_OUT" "$REC_DIR/logs/kr-install.log"
    run "$VM" "awk '{ print \$1 \"  /stage\" \$2 }' $(q "$STAGE/usr/share/kerber-rust/install-manifest") > $(q "$VT/stage.manifest") 2>/dev/null; true"
    SRUN="docker run --rm -i --name $N-check --network none -v $(q "$STAGE"):/stage:ro -v $(q "$VT/stage.manifest"):/stage.manifest:ro $N:buildenv"
    vpush "strings-check.sh" "$FIELD_LIB/strings-check.sh" "cat > $VT/strings-check.sh"
    check strings.control rc run "$VM" "$SRUN sh -s -- --control < $(q "$VT/strings-check.sh")"
    check strings.manifest '^programs in /stage.manifest: [1-9][0-9]*, all [1-9][0-9]* checked$' run "$VM" "$SRUN sh -s -- --manifest /stage.manifest < $(q "$VT/strings-check.sh")"
    check kr.glibc '^GLIBC_[0-9.]+ /stage/' run "$VM" "$SRUN sh -c 'for p in \$(awk \"{ print \\\$2 }\" /stage.manifest | grep -E \"/s?bin/\"); do printf \"%s %s\\n\" \"\$(objdump -T \$p | grep -oE \"GLIBC_[0-9.]+\" | sort -uV | tail -n 1)\" \$p; done'"
    FLOOR=$(sed -n 's/^GLIBC_\([0-9.]*\) .*/\1/p' "$LAST_OUT" | sort -uV | tail -n 1)

    section "4. the images: KLLDAP's own (MIT, for the dump), then F3's one hunk with the staging in krb5-server's place"
    image old
    check image.rust.hunk '^\+COPY --from=kerber-rust / /$' run "$VM" "$PY_VM hunk $(q "$SRC/Dockerfile") $(q "$VT/swap.Dockerfile")"
    image rust "$VT/swap.Dockerfile" "--build-context kerber-rust=$(q "$STAGE")"
    check image.rust.packages '^package krb5-server is not installed$' run "$VM" "docker run --rm --network none --entrypoint sh $N:rust -c 'rpm -q glibc krb5-libs krb5-workstation libkadm5 && ! rpm -q krb5-server && klist -V'"
    observelast obs.image.krb5 'krb5-server-[^ ]+|package krb5-server is not installed'
    G=$(sed -n 's/^glibc-\([0-9.]*\)-.*/\1/p' "$LAST_OUT" | head -n 1)
    check glibc.floor '^glibc floor GLIBC_[0-9.]+, not above the image.s [0-9.]+$' host "[ -n '$FLOOR' ] && [ -n '$G' ] && [ \"\$(printf '%s\n' '$FLOOR' '$G' | sort -V | tail -n 1)\" = '$G' ] && echo \"glibc floor GLIBC_$FLOOR, not above the image's $G\" || { echo \"glibc floor GLIBC_${FLOOR:-?}, the image's ${G:-?}\"; exit 1; }"
    MODES="/ /usr /usr/sbin /usr/lib /usr/share /etc /var /var/kerberos /var/kerberos/krb5kdc /var/log/krb5 /app /data"
    check image.rust.modes rc run "$VM" "diff <(docker run --rm --network none --entrypoint stat $N:old -c '%a %U:%G %n' $MODES) <(docker run --rm --network none --entrypoint stat $N:rust -c '%a %U:%G %n' $MODES) && echo 'modes and owners as in the MIT image:' && docker run --rm --network none --entrypoint stat $N:rust -c '%a %U:%G %n' $MODES"
    check image.rust.manifest '^manifest: [1-9][0-9]* files as staged$' run "$VM" "docker run --rm --network none --entrypoint sh $N:rust -c 'sha256sum -c /usr/share/kerber-rust/install-manifest && echo \"manifest: \$(wc -l < /usr/share/kerber-rust/install-manifest) files as staged\"'"
else
    section "3. KLLDAP's image as it is, MIT krb5-server inside"
    image mit
    observe obs.image.krb5 'krb5-server-[^ ]+|package krb5-server is not installed' run "$VM" "docker run --rm --network none --entrypoint sh $N:mit -c 'rpm -q glibc krb5-server krb5-libs krb5-workstation libkadm5; klist -V'"
fi

section "5. the FFI lane (gate/kdc-sandbox.sh + cargo test -p lldap-kerberos -- --ignored) on F3-MIT's two clients"
for e in alma10 f43; do
    ffienv "$e" ''
    if [ "$LEG" = rust ]; then
        ffienv "$e" swap
        lane "$e" "$N:ffi-$e-swap"
        check "ffi.$e.ours" '^ours: 5 of 5$' host "awk 'NR == FNR { m[\$2] = \$1; next } /^== prog / { n++; if (m[\"/usr/sbin/\" \$3] == \$5) k++ } END { printf \"ours: %d of %d\\n\", k, n; exit !(n == 5 && k == n) }' <($LABQ ssh $VM -- cat $(q "$STAGE/usr/share/kerber-rust/install-manifest")) $(q "$REC_DIR/logs/lane-$e.log")"
    else
        lane "$e" "$N:ffi-$e"
    fi
done

# the phase-80 fixture, pushed only now so it is not under the VT mount during the ref build and the lanes
check input.fixture.push '^files: [1-9][0-9]*$' host "set -o pipefail; (cd $(q "$FIX") && tar -c .) | $LABQ ssh $VM -- 'rm -rf $VT/fixture && mkdir -p $VT/fixture && tar -x -C $VT/fixture && echo \"files: \$(find $VT/fixture -type f | wc -l)\"'"
FIXV=$VT/fixture
KDC=$FIXV/krb5kdc
if [ "$LEG" = rust ]; then
    section "6. the fixture's KDC migrated as docs/install.md 'In a container' says (blocks 1 to 3): the MIT image dumps, ours loads"
    KDC=$VT/fixture-migrated/krb5kdc
    check migrate.copy rc run "$VM" "rm -rf $(q "$VT/fixture-migrated") && mkdir -p $(q "$VT/fixture-migrated") && cp -a $(q "$FIXV/krb5kdc") $(q "$KDC") && ls -lan $(q "$KDC")"
    check doc.migrate.blocks 'line:4' host "python3 -B $(q "$DOCB") count $(q "$STATE/install.md") '### In a container'"
    for b in 1 2 3; do
        case $b in
            1) opts="--set REALM=$(q "$REALM") --set VOLUME=$(q "$KDC") --set OLD_IMAGE=$N:old --set NEW_IMAGE=$N:rust" ;;
            2) opts="--drop '^docker stop '" ;;
            3) opts='' ;;
        esac
        check "doc.migrate-$b.script" rc host "python3 -B $(q "$DOCB") script $(q "$STATE/install.md") '### In a container' $b $opts > $(q "$STATE/migrate-$b.sh")"
        vpush "migrate-$b.sh" "$STATE/migrate-$b.sh" "cat > $VT/migrate-$b.sh"
    done
    note "the blocks run in one bash session on the VM, as a reader pastes them into one terminal: block 1's names and block 2's OWNER reach block 3; block 2's 'docker stop' is not run; block 4 waits for step 10"
    run "$VM" "cd $(q "$VT") && . ./migrate-1.sh > migrate-1.out 2>&1; . ./migrate-2.sh > migrate-2.out 2>&1; . ./migrate-3.sh > migrate-3.out 2>&1; cat migrate-1.out migrate-2.out migrate-3.out"
    for b in 1 2 3; do
        run "$VM" "cat $(q "$VT/migrate-$b.out")"; cp "$LAST_OUT" "$STATE/migrate-$b.out"
        python3 -B "$DOCB" results "$STATE/migrate-$b.out" > "$STATE/migrate-$b.results" || _checkrow "doc.migrate-$b" FAIL units - "no command of block $b ran"
        while IFS=$'\t' read -r i rc nout first; do
            _checkrow "doc.migrate-$b.$i" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" rc "$rc" "rc=$rc, $nout output lines: $first"
        done < "$STATE/migrate-$b.results"
    done
    check migrate.principals '^principals: [1-9][0-9]*, the dump.s$' run "$VM" "a=\$(docker run --rm --network none --entrypoint /usr/sbin/kadmin.local -v $(q "$KDC"):/var/kerberos/krb5kdc $N:rust -r $(q "$REALM") -q listprincs | grep -E '^[^ ]+@[^ ]+\$' | sort) && b=\$(awk '\$1 == \"princ\" { print \$7 }' $(q "$KDC/mit-realm.dump") | sort) && [ -n \"\$a\" ] && [ \"\$a\" = \"\$b\" ] && echo \"principals: \$(printf '%s\n' \"\$a\" | wc -l), the dump's\" && printf '%s\n' \"\$a\""
    grep -E '^[^ ]+@[^ ]+$' "$LAST_OUT" | sort > "$STATE/principals.migrated"
fi

section "7. the image booted once, as the gate boots it (fresh volumes, no published port): the observations"
check boot.run rc run "$VM" "docker network create $N-net && docker run -d --name $N-boot --network $N-net --env-file $(q "$VTS/boot.env") -v $N-boot-data:/data -v $N-boot-kdc:/var/kerberos/krb5kdc $N:$LEG"
check boot.healthy '^healthy, the KDC leg too, after [0-9]+ s$' run "$VM" "for i in \$(seq 1 120); do if docker exec $N-boot /app/lldap healthcheck --config-file /data/lldap_config.toml --kerberos > /dev/null 2>&1 && docker exec $N-boot test -s /var/log/krb5/kadmind.log; then echo \"healthy, the KDC leg too, after \$i s\"; exit 0; fi; sleep 1; done; echo 'not healthy in 120 s'; exit 1"
observe obs.boot.sockets 'sockets: .*' run "$VM" "set -o pipefail; docker exec $N-boot sh -c 'for f in tcp tcp6 udp udp6; do awk -v p=\$f \"NR > 1 { print p, \\\$2, \\\$4 }\" /proc/net/\$f; done' | $PY_VM sockets"
observe obs.boot.logs 'logs: .*' run "$VM" "docker exec $N-boot sh -c 'cd /var/log/krb5 && echo logs: \$(stat -c \"%n %a %u:%g\" kadmind.log krb5kdc.log); echo kdb: \$(ls -A /var/kerberos/krb5kdc)'"
observelast obs.boot.kdb 'kdb: .*'
observe obs.boot.json 'stdout JSON lines: [0-9]+' run "$VM" "printf 'stdout JSON lines: %s\n' \"\$(docker logs $N-boot 2> /dev/null | grep -c '^{')\""
run "$VM" "docker rm -f $N-boot && docker volume rm $N-boot-data $N-boot-kdc && docker network rm $N-net"

section "8. KLLDAP's gate, all phases (phase 80: the fixture's data as it is, its KDC $([ "$LEG" = rust ] && echo "as migrated" || echo "as it is"))"
gate all "$FIXV/data" "$KDC"
sed -E 's/^[0-9]+\.[0-9]+ //' "$REC_DIR/logs/gate-all.log" | awk '/^=== phase: /{ p = 1 } p && !/^Logs: /' > "$REC_DIR/gate-table.txt"
check gate.table '^not PASS: the fixture.s two pinned key_seed lines, nothing else$' host "grep -E '^\[(FAIL|SKIP)\]' $(q "$REC_DIR/gate-table.txt") | diff - <(printf '%s\n' $(q "$KEYSEED_FAILS")) && echo \"not PASS: the fixture's two pinned key_seed lines, nothing else\"; grep '^Gate results: ' $(q "$REC_DIR/gate-table.txt")"
check gate.keyseed 'The private key has not changed' run "$VM" "grep -h -m 1 'Error: ' $(q "$VT/gate-results/$RID/80-migration-boot/force-reset.log")"

section "9. phase 80 on a copy of the fixture's data with a fresh key_seed (its precondition), the KDC as in step 8"
vpush "freshkey.key-seed" "$T/secrets/freshkey.key-seed" "umask 077 && cat > $VTS/freshkey.key-seed"
check phase80.copy '^key_seed replaced' run "$VM" "rm -rf $(q "$VT/fixture-freshkey") && mkdir -p $(q "$VT/fixture-freshkey") && cp -a $(q "$FIXV/data") $(q "$VT/fixture-freshkey/data") && $PY_VM keyseed $(q "$VT/fixture-freshkey/data/lldap_config.toml") $(q "$VTS/freshkey.key-seed")"
gate phase80 "$VT/fixture-freshkey/data" "$KDC" 80-migration
check phase80.result 'Gate results: 4 passed, 0 failed, 0 skipped$' host "grep -E 'Gate results: ' $(q "$REC_DIR/logs/gate-phase80.log")"

if [ "$LEG" = rust ]; then
    section "10. docs/install.md 'In a container', block 4: the realm has served from the new image, so the dump and MIT's database are removed"
    check doc.migrate-4.script rc host "python3 -B $(q "$DOCB") script $(q "$STATE/install.md") '### In a container' 4 --session $(q "VOLUME=$(q "$KDC")") --session $(q "NEW_IMAGE=$N:rust") > $(q "$STATE/migrate-4.sh")"
    vpush "migrate-4.sh" "$STATE/migrate-4.sh" "cat > $VT/migrate-4.sh"
    note "block 4 runs in a session that has what block 1 set (VOLUME, NEW_IMAGE), as the reader's terminal does"
    run "$VM" "cd $(q "$VT") && . ./migrate-4.sh > migrate-4.out 2>&1; cat migrate-4.out"; cp "$LAST_OUT" "$STATE/migrate-4.out"
    python3 -B "$DOCB" results "$STATE/migrate-4.out" > "$STATE/migrate-4.results" || _checkrow doc.migrate-4 FAIL units - "no command of block 4 ran"
    while IFS=$'\t' read -r i rc nout first; do
        _checkrow "doc.migrate-4.$i" "$([ "$rc" = 0 ] && echo PASS || echo FAIL)" rc "$rc" "rc=$rc, $nout output lines: $first"
    done < "$STATE/migrate-4.results"
    check migrate.removed '^gone: mit-realm\.dump, mit-realm\.dump\.dump_ok, mit-db2$' run "$VM" "cd $(q "$KDC") && for f in mit-realm.dump mit-realm.dump.dump_ok mit-db2; do if [ -e \"\$f\" ] || [ -L \"\$f\" ]; then echo \"still there: \$f\"; exit 1; fi; done; echo 'gone: mit-realm.dump, mit-realm.dump.dump_ok, mit-db2'"
    check migrate.kept '^principals: [1-9][0-9]*, as after the load$' run "$VM" "a=\$(docker run --rm --network none --entrypoint /usr/sbin/kadmin.local -v $(q "$KDC"):/var/kerberos/krb5kdc $N:rust -r $(q "$REALM") -q listprincs | grep -E '^[^ ]+@[^ ]+\$' | sort) && [ -n \"\$a\" ] && echo \"principals: \$(printf '%s\n' \"\$a\" | wc -l), as after the load\" && printf '%s\n' \"\$a\""
    grep -E '^[^ ]+@[^ ]+$' "$LAST_OUT" | sort > "$STATE/principals.kept"
    sides migrate.kept.same migrated "$STATE/principals.migrated" kept "$STATE/principals.kept" \
        && check migrate.kept.same rc host "diff $(q "$STATE/principals.migrated") $(q "$STATE/principals.kept") && echo 'same principals as after the load'"

    section "11. against the MIT leg: this run's, else runs/mit-latest (neither: each comparison NOT-RUN, a FAIL)"
    REF_DIR=''
    if [ -f "$FIELD_RUN/klldap-swap/mit/result" ]; then REF_DIR=$FIELD_RUN/klldap-swap/mit
    elif [ -d "$LAB_HOME/runs/mit-latest/klldap-swap/mit" ]; then REF_DIR=$LAB_HOME/runs/mit-latest/klldap-swap/mit; fi
    note "the MIT leg compared with: ${REF_DIR:-none}$([ -n "$REF_DIR" ] && echo " ($(cat "$REF_DIR/result" 2> /dev/null))")"
    cmpref app app.sha256
    cmpref ffi ffi.counts
    cmpref gate.table gate-table.txt
fi

section "12. postflight: alien's docker is unchanged (nothing built or ran there), the VM's leg artifacts go, and no injected secret reached an image layer or VT"
aliendocker > "$T/alien-docker.after"
check alien.docker.unchanged '^alien docker: unchanged$' host "diff $(q "$T/alien-docker.before") $(q "$T/alien-docker.after") > $(q "$T/alien-docker.diff") && echo 'alien docker: unchanged' || { echo 'alien docker CHANGED:'; cat $(q "$T/alien-docker.diff"); exit 1; }"
check alien.docker.control '^control: the check reds on an altered before$' host "head -n -1 $(q "$T/alien-docker.before") > $(q "$T/alien-docker.altered") 2>/dev/null; if diff -q $(q "$T/alien-docker.altered") $(q "$T/alien-docker.after") > /dev/null 2>&1; then echo 'control: a dropped line did not change the diff -- the check is blind'; exit 1; else echo 'control: the check reds on an altered before'; fi"
# every built image's history into the records, so the secrets.leg scan below reads it for a secret baked into a layer
run "$VM" "for t in \$(docker images --format '{{.Repository}}:{{.Tag}}' $N | sort -u); do echo \"=== \$t ===\"; docker history --no-trunc \"\$t\" 2>&1; done"
cp "$LAST_OUT" "$REC_DIR/logs/image-history.log"
check image.histories '^histories: [1-9][0-9]* images in the records$' host "n=\$(grep -c '^=== ' $(q "$REC_DIR/logs/image-history.log")); [ \"\$n\" -ge 1 ] && echo \"histories: \$n images in the records\" || { echo 'no image histories captured'; exit 1; }"
check secrets.vt.clean '^VT holds none of the injected secrets$' run "$VM" "s=\$(sed -n 's/^LLDAP_[A-Z_]*=\([0-9a-f]\{32,\}\)\$/\1/p' $(q "$VTS/boot.env"); cat $(q "$VTS/fixture-admin.password")); set -- \$s; [ \$# = 4 ] || { echo \"injected secrets to look for: \$#, not 4\"; exit 1; }; h=; for v in \$s; do f=\$(grep -rlF -e \"\$v\" $(q "$VT") 2>/dev/null) && h=\"\$h \$f\"; done; if [ -n \"\$h\" ]; then echo \"an injected secret is under VT:\$h\"; exit 1; fi; echo 'VT holds none of the injected secrets'"
check secrets.leg rc host "KERBER_LAB_HOME=$(q "$T/scan") FIELD_ADLAB_ENV=/dev/null python3 -B $(q "$FIELD_LIB/scan-secrets.py") $(q "$REC_DIR")"
check secrets.history.control '^control: a planted key_seed reds the history scan$' host "d=\$(mktemp -d $(q "$T/hist-ctl.XXXXXX")); cp $(q "$REC_DIR/logs/image-history.log") \"\$d/image-history.log\"; sed -n 's/^LLDAP_KEY_SEED=/planted /p' $(q "$T/scan/secrets/run.env") >> \"\$d/image-history.log\"; if KERBER_LAB_HOME=$(q "$T/scan") FIELD_ADLAB_ENV=/dev/null python3 -B $(q "$FIELD_LIB/scan-secrets.py") \"\$d\" > /dev/null 2>&1; then rm -rf \"\$d\"; echo 'control: the planted key_seed did not red the scan'; exit 1; fi; rm -rf \"\$d\"; echo 'control: a planted key_seed reds the history scan'"
# the VM's docker inventory again, before cleanup removes the leg's artifacts
run "$VM" "docker ps -a --format '{{.Names}} {{.Image}}'; docker images --format '{{.Repository}}:{{.Tag}} {{.ID}}'; docker volume ls -q; docker network ls --format '{{.Name}}'"
finish
