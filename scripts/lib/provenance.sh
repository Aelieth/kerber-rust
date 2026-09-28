# Stamp every gate artefact with the tested tree. Source after `cd "$ROOT"`.
# shellcheck shell=bash

# A silent `set -e` death names its cell: the failing command becomes a GitHub
# workflow `::error` line (a check-run annotation, readable without a token by
# `scripts/ci-status.py`) that also reads as plain text locally. Deliberate
# failures under `set +e` are skipped; `log … error; exit 1` paths already say
# what failed on their own line.
_gate_err() {
    local status=$1 line=$2 cmd=$3 src=$4 title=
    case $- in *e*) ;; *) return 0 ;; esac
    src=${src#"$PWD"/}
    src=${src#./}
    # gate-err-trap-selftest's probe-gate.sh is a fixture; tag so ci-status
    # --save does not treat its ::error lines as product failures.
    case "${src##*/}" in
        probe-gate.sh) title=',title=fixture' ;;
    esac
    printf '::error file=%s,line=%s%s::%s: exit %s at line %s: %s\n' \
        "$src" "$line" "$title" "${src##*/}" "$status" "$line" "$cmd"
}
trap '_gate_err "$?" "$LINENO" "$BASH_COMMAND" "${BASH_SOURCE[0]}"' ERR

# _prov_memo_put ID SHA: keep image ID's kadm5.acl hash in the runner's memo, when it made one.
_prov_memo_put() {
    [ -n "${KERBER_PROV_MEMO:-}" ] || return 0
    printf '%s %s\n' "$1" "$2" >"$KERBER_PROV_MEMO"
}

head_sha="$(git rev-parse HEAD)"
_prov_dir="${KERBER_SCRATCH:-${TMPDIR:-/tmp}}"
mkdir -p "$_prov_dir"
if [ -n "${KERBER_TREE_SHA:-}" ]; then
    tree_sha="$KERBER_TREE_SHA"
else
    _prov_idx="$(mktemp "$_prov_dir/kerber-prov.XXXXXX")"
    rm -f "$_prov_idx"
    # working/ is gitignored; naming it in the pathspec makes `git add` exit 1.
    GIT_INDEX_FILE="$_prov_idx" git add -A -- . >/dev/null
    tree_sha="$(GIT_INDEX_FILE="$_prov_idx" git write-tree)"
    rm -f "$_prov_idx"
fi
if git status --porcelain --untracked-files=normal -- ':!working' | grep -q .; then
    dirty=yes
else
    dirty=no
fi
captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
image="unavailable"
acl_sha256_tree=""
acl_sha256_image=""
if [ -f harness/kadm5.acl ]; then
    acl_sha256_tree="$(sha256sum harness/kadm5.acl | awk '{print $1}')"
fi
if command -v docker >/dev/null 2>&1; then
    if docker image inspect kerber-rust-mit-kdc:1.22.2 >/dev/null 2>&1; then
        image="$(docker image inspect kerber-rust-mit-kdc:1.22.2 --format '{{.Id}} {{.Created}}')"
        _img_id="$(echo "$image" | awk '{print $1}')"
        # The image's kadm5.acl hash costs a `docker run`. A runner that stamps many artefacts
        # (checkpoint.sh, red-at-sha.sh) makes one memo file with mktemp under its KERBER_SCRATCH,
        # exports it as KERBER_PROV_MEMO and removes it on exit; nothing else writes a memo.
        acl_sha256_image=""
        _memo_id=""
        _memo_sha=""
        if [ -n "${KERBER_PROV_MEMO:-}" ] && [ -f "$KERBER_PROV_MEMO" ]; then
            read -r _memo_id _memo_sha <"$KERBER_PROV_MEMO" || true
        fi
        [ "$_memo_id" != "$_img_id" ] || acl_sha256_image="$_memo_sha"
        if [ -z "$acl_sha256_image" ]; then
            acl_sha256_image="$(
                docker run --rm --entrypoint cat kerber-rust-mit-kdc:1.22.2 \
                    /var/kerberos/krb5kdc/kadm5.acl | sha256sum | awk '{print $1}'
            )"
            _prov_memo_put "$_img_id" "$acl_sha256_image"
        fi
        if [ "$acl_sha256_image" != "$acl_sha256_tree" ]; then
            echo "stale MIT image; rebuild from harness/" >&2
            echo "acl_sha256_tree=$acl_sha256_tree" >&2
            echo "acl_sha256_image=$acl_sha256_image" >&2
            exit 1
        fi
    elif [ "${KERBER_NO_IMAGE:-}" = 1 ]; then
        image="unavailable"
    else
        echo "MIT image kerber-rust-mit-kdc:1.22.2 missing; restore the CI cache or rebuild from harness/" >&2
        exit 2
    fi
elif [ "${KERBER_NO_IMAGE:-}" = 1 ]; then
    image="unavailable"
else
    echo "docker not available" >&2
    exit 2
fi
echo "==== provenance ===="
echo "head_sha=$head_sha"
echo "tree_sha=$tree_sha"
echo "dirty=$dirty"
echo "captured_at=$captured_at"
echo "image=$image"
echo "acl_sha256_tree=$acl_sha256_tree"
echo "acl_sha256_image=$acl_sha256_image"
