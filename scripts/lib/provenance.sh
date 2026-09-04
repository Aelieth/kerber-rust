# Stamp every gate artefact with the tested tree. Source after `cd "$ROOT"`.
# shellcheck shell=bash

head_sha="$(git rev-parse HEAD)"
_prov_idx="$(mktemp)"
rm -f "$_prov_idx"
# working/ is gitignored; naming it in the pathspec makes `git add` exit 1.
GIT_INDEX_FILE="$_prov_idx" git add -A -- . >/dev/null
tree_sha="$(GIT_INDEX_FILE="$_prov_idx" git write-tree)"
rm -f "$_prov_idx"
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
        acl_sha256_image="$(
            docker run --rm --entrypoint cat kerber-rust-mit-kdc:1.22.2 \
                /var/kerberos/krb5kdc/kadm5.acl | sha256sum | awk '{print $1}'
        )"
        if [ "$acl_sha256_image" != "$acl_sha256_tree" ]; then
            echo "stale MIT image; rebuild from harness/" >&2
            echo "acl_sha256_tree=$acl_sha256_tree" >&2
            echo "acl_sha256_image=$acl_sha256_image" >&2
            exit 1
        fi
    fi
fi
echo "==== provenance ===="
echo "head_sha=$head_sha"
echo "tree_sha=$tree_sha"
echo "dirty=$dirty"
echo "captured_at=$captured_at"
echo "image=$image"
echo "acl_sha256_tree=$acl_sha256_tree"
echo "acl_sha256_image=$acl_sha256_image"
