"""The self-test of the bash lexers: echo-only `if` arms and host `/tmp` writes."""

from __future__ import annotations

import signal

from ..common import ROOT, SCRIPTS
from ..shell import (
    _join_shell_continuations, check_kadmin_q_via_lib, check_no_duplicate_functions, check_no_host_tmp_writes,
    informational_if_starts,
)
from .common import _must_die, _must_die_msg


def _self_test_shell() -> None:
    echo_if = 'if ! grep -F foo /tmp/x; then\n    echo "informational fallback"\nfi\n'
    if not informational_if_starts(echo_if):
        raise AssertionError("informational echo if must be a violation")
    ok_if = 'if ! grep -F foo /tmp/x; then\n    exit 1\nfi\n'
    if informational_if_starts(ok_if):
        raise AssertionError("if with exit must pass")
    gss_shape = 'if [ "$ok" != 1 ]; then\n    echo "settled live"\nfi\n'
    if not informational_if_starts(gss_shape):
        raise AssertionError("if [ ] echo-only must be a violation")
    quoted_return = 'if true; then\n    echo "return from helper"\nfi\n'
    if not informational_if_starts(quoted_return):
        raise AssertionError("return inside quotes must not excuse echo-only")
    else_echo = 'if true; then\n    :\nelse\n    echo only\nfi\n'
    if not informational_if_starts(else_echo):
        raise AssertionError("else echo-only must be a violation")
    nested = 'if true; then\n    if false; then\n        echo inner\n    fi\n    exit 1\nfi\n'
    nested_hits = informational_if_starts(nested)
    if not nested_hits:
        raise AssertionError("nested echo-only if must be a violation")
    if nested_hits[0] == 1:
        raise AssertionError("nested fi must not pop the outer if")
    colon_if = 'if true; then\n    :\nfi\n'
    if not informational_if_starts(colon_if):
        raise AssertionError("colon-only if must be a violation")
    oneliner = 'if [ "$ok" != 1 ]; then echo settled; fi\n'
    if not informational_if_starts(oneliner):
        raise AssertionError("one-liner echo-only must be a violation")
    mixed = 'if X; then\n    exit 1\nelif Y; then\n    echo only\nfi\n'
    if not informational_if_starts(mixed):
        raise AssertionError("mixed exit/echo chain must be a violation")
    echo_else_exit = 'if true; then\n    echo only\nelse\n    exit 0\nfi\n'
    if not informational_if_starts(echo_else_exit):
        raise AssertionError("echo then else exit must be a violation")
    multi = 'if [ "$a" = 1 ] ||\n   [ "$b" = 2 ]; then\n    echo hi\nfi\n'
    if not informational_if_starts(multi):
        raise AssertionError("multi-line condition echo-only must be a violation")
    helper_snip = 'if ! wait_ready; then\n    echo skip\nfi\n'
    if not informational_if_starts(helper_snip):
        raise AssertionError("helper-file echo-only snippet must be a violation")
    ok_mixed_no_echo = 'if X; then\n    exit 1\nelif Y; then\n    exit 2\nfi\n'
    if informational_if_starts(ok_mixed_no_echo):
        raise AssertionError("exit/exit chain must pass")
    oneliner_elif = (
        'if X; then exit 1; elif Y; then echo hi; elif Z; then exit 2; fi\n'
    )
    if informational_if_starts(oneliner_elif) != [1]:
        raise AssertionError("one-line ≥2-elif middle echo must be a hit")
    tee_echo = 'if true; then\n    echo skip | tee /tmp/x\nfi\n'
    if not informational_if_starts(tee_echo):
        raise AssertionError("echo | tee without assert must be a violation")
    redir_echo = 'if true; then\n    echo skip > /tmp/x\nfi\n'
    if not informational_if_starts(redir_echo):
        raise AssertionError("echo > file without assert must be a violation")
    assign_echo = 'if true; then\n    n=1\n    echo skip\nfi\n'
    if not informational_if_starts(assign_echo):
        raise AssertionError("assignment must not excuse echo-only")
    brace_echo = 'if true; then\n    { echo x; } > /tmp/x\nfi\n'
    if not informational_if_starts(brace_echo):
        raise AssertionError("{ echo; } redirect must be a violation")
    subshell_echo = 'if true; then\n    ( echo x ) > /tmp/x\nfi\n'
    if not informational_if_starts(subshell_echo):
        raise AssertionError("( echo ) redirect must be a violation")
    heredoc = 'if true; then\n    cat <<EOF > /tmp/x\nhi\nEOF\nfi\n'
    if not informational_if_starts(heredoc):
        raise AssertionError("heredoc arm must be a violation")
    cmp_ok = 'if true; then\n    cmp -s a b\nfi\n'
    if informational_if_starts(cmp_ok):
        raise AssertionError("cmp arm must assert")
    test_ok = 'if true; then\n    [ "$x" = 1 ]\nfi\n'
    if informational_if_starts(test_ok):
        raise AssertionError("[ ] arm must assert")
    unavail_ok = 'if true; then\n    unavailable "x"\nfi\n'
    if informational_if_starts(unavail_ok):
        raise AssertionError("unavailable arm must assert")
    for i, snippet in enumerate(
        (
            'if true; then\n    y=$( grep foo bar )\n    echo skip\nfi\n',
            'if true; then\n    echo see grep output\nfi\n',
            'if true; then\n    echo skip > test.log\nfi\n',
            'if true; then\n    echo run test suite\nfi\n',
            'if true; then\n    echo tcpdump unavailable\nfi\n',
            'if true; then\n    echo will exit later\nfi\n',
            'if true; then\n    ( exit 1 ) || true\n    echo skip\nfi\n',
            'if true; then\n    echo skip | grep -q skip\nfi\n',
            'if true; then\n    echo skip\n    test -n "x"\nfi\n',
            'if true; then\n    echo skip\n    cmp -s /dev/null /dev/null\nfi\n',
            'if true; then\n    echo skip | tee /tmp/x\n    [ -s /tmp/x ]\nfi\n',
        )
    ):
        if not informational_if_starts(snippet):
            raise AssertionError(f"counter-example {i} must be informational")
    for i, snippet in enumerate(
        (
            'if true; then\n    grep -q x f || { echo skip; }\nfi\n',
            'if true; then\n    grep -q x f || :\nfi\n',
            'if true; then\n    echo skip > "$OUT/x.log"\n    grep -q skip "$OUT/x.log"\nfi\n',
            'if true; then\n    /bin/echo skip\nfi\n',
            'if true; then\n    log_info "skipping"\nfi\n',
            'if true; then\n    [ -n "$x" ] && echo skip\nfi\n',
            'case "$x" in\n    *) echo skip ;;\nesac\n',
            'case "$x" in\n    a)\n        echo skip\n        ;;\n    *) die x ;;\nesac\n',
        )
    ):
        if not informational_if_starts(snippet):
            raise AssertionError(f"round-2 counter-example {i} must be informational")
    for i, snippet in enumerate(
        (
            'if true; then\n    grep -q x f || die x\nfi\n',
            'if true; then\n    [ -n "$x" ] && exit 1\nfi\n',
            'if true; then\n    docker exec c true > "$OUT/x.log"\n    grep -q ok "$OUT/x.log"\nfi\n',
            'if true; then\n    grep -q x f || { log "g" "error" x; exit 1; }\nfi\n',
            'case "$x" in\n    *) die x ;;\nesac\n',
        )
    ):
        if informational_if_starts(snippet):
            raise AssertionError(f"round-2 positive control {i} must assert")
    skip_scoped = (
        'if [ "${KERBER_REQUIRE_NETEM:-0}" = 1 ]; then\n'
        '    die "required"\n'
        "fi\n"
        "if true; then\n"
        '    log "g" "skip" "foo missing"\n'
        "fi\n"
    )
    if not informational_if_starts(skip_scoped):
        raise AssertionError("a skip that names no enforced requirement must be informational")
    skip_require = (
        'if [ "${KERBER_REQUIRE_NETEM:-0}" = 1 ]; then\n'
        '    die "required"\n'
        "fi\n"
        "if true; then\n"
        '    log "g" "skip" "netem"\n'
        "    echo hi\n"
        "fi\n"
    )
    if informational_if_starts(skip_require):
        raise AssertionError("log skip with REQUIRE die must pass")
    skip_bare = 'if true; then\n    log "g" "skip" "netem"\n    echo hi\nfi\n'
    if not informational_if_starts(skip_bare):
        raise AssertionError("log skip without REQUIRE die must be informational")

    class _Alarm(Exception):
        pass

    def _on_alarm(_signum, _frame) -> None:
        raise _Alarm

    three_or = (
        'if [ "$a" = 1 ] ||\n'
        '   [ "$b" = 2 ] ||\n'
        '   [ "$c" = 3 ]; then\n'
        " echo hi\n"
        "fi\n"
    )
    old = signal.signal(signal.SIGALRM, _on_alarm)
    signal.alarm(5)
    try:
        three_hits = informational_if_starts(three_or)
    except _Alarm as exc:
        raise AssertionError("3-way || join hung") from exc
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)
    if three_hits != [1]:
        raise AssertionError(f"3-way || must be [1], got {three_hits}")
    joined = _join_shell_continuations("a &&\nb &&\nc\n")
    if "a && b && c" not in joined.replace("\n", " "):
        raise AssertionError(f"3-way && join failed: {joined!r}")
    check_no_host_tmp_writes(
        'SCRATCH="${KERBER_SCRATCH:-/tmp/kerber-x-gate}"\n'
        "docker exec n sh -c 'cat >/tmp/in-container'\n",
        "ok-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cc -o x x.c 2>/tmp/kadm5-cc.err\n",
        "kadmin-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cp x /tmp/foo\n",
        "cp-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "tee /tmp/out.log\n",
        "tee-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "echo $(cat >/tmp/x)\n",
        "subshell-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "python3 -c '\nprint(1)\n'\necho x > /tmp/after-multiline\n",
        "multiline-quote-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "docker exec n sh -c 'cat >/tmp/in <<EOF\nbody\nEOF'\necho x > /tmp/after-heredoc\n",
        "quoted-heredoc-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        None,
        "lib",
        {"lib/gate-common.sh": "echo x > /tmp/host-out\n"},
    )
    _must_die(
        check_no_host_tmp_writes,
        "docker exec n sh -c 'true' >/tmp/host-out\n",
        "docker-host-redir-tmp-gate.sh",
    )
    _must_die(check_no_host_tmp_writes, 'tmp="$(mktemp -d)"\n', "bare-mktemp.sh")
    _must_die(check_no_host_tmp_writes, "t=$(mktemp)\n", "bare-mktemp-file.sh")
    check_no_host_tmp_writes(
        'TMP="$(mktemp -d "${KERBER_SCRATCH:-${TMPDIR:-/tmp}}/x.XXXXXX")"\n'
        'idx="$(mktemp "$dir/kerber-prov.XXXXXX")"\n'
        'd="$(mktemp -d -p "$SCRATCH")"\n'
        "docker exec n sh -c 'mktemp -d'\n",
        "ok-mktemp.sh",
    )
    check_no_host_tmp_writes(
        "docker exec n sh -c 'kill /tmp/krb5-kdc; : >/tmp/in-container'\n"
        "docker exec -d n \\\n"
        "    sh -c '/tmp/krb5-kdc >/tmp/kdc-r18.log 2>&1'\n",
        "ok-r18-kill-tmp-gate.sh",
    )
    _probe_dir = ROOT / "working" / "logs" / "w1-sweep" / "a2-r2-audit" / "scan-probe"
    for _probe_name in (
        "differential-gate.sh",
        "kadmin-gate.sh",
        "renew-gate.sh",
        "s4u-mit-gate.sh",
    ):
        _probe = _probe_dir / _probe_name
        if _probe.is_file():
            _must_die(check_no_host_tmp_writes, _probe.read_text(), _probe_name)
        _must_die(
            check_no_host_tmp_writes,
            (SCRIPTS / _probe_name).read_text()
            + f"\necho probe > /tmp/host-probe-{_probe_name}\n",
            f"probe-{_probe_name}",
        )
    _must_die(
        check_no_host_tmp_writes,
        "# ignore <<EOF in a comment\necho x > /tmp/after-comment-heredoc\n",
        "comment-heredoc-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        "cat <<<ignored\necho x > /tmp/after-herestring\n",
        "herestring-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        'echo >"/tmp/quoted-redir"\n',
        "quoted-redir-tmp-gate.sh",
    )
    _must_die(
        check_no_host_tmp_writes,
        'cp x "/tmp/quoted-cp"\n',
        "quoted-cp-tmp-gate.sh",
    )
    check_no_host_tmp_writes(
        'echo "cat <<EOF"\necho ok\ncat <<<hello\n# <<EOF\n',
        "ok-quoted-and-comment-heredoc.sh",
    )
    # S6.1: a gate's own SCRATCH=, byte-identical shell functions, direct kadmin queries.
    check_no_host_tmp_writes(files={"a-gate.sh": "echo ok\n", "lib/gate-common.sh": 'SCRATCH="$x"\n'}, scratch_allow=0)
    _must_die_msg("1 gate(s) assign SCRATCH=", check_no_host_tmp_writes,
                  files={"a-gate.sh": 'SCRATCH="${KERBER_SCRATCH:-x}"\n', "b-gate.sh": "export KERBER_SCRATCH=y\n"},
                  scratch_allow=0)
    dup_f = "f() {\n    echo a\n}\n"
    check_no_duplicate_functions({"a.sh": dup_f, "b.sh": "f() {\n    echo b\n}\n"}, allow=0)
    _must_die_msg("1 duplicate shell function copies", check_no_duplicate_functions,
                  {"a.sh": dup_f, "lib/c.sh": dup_f}, allow=0)
    check_no_duplicate_functions({"a.sh": dup_f, "lib/c.sh": dup_f}, allow=1)
    kq_files = {
        "a-gate.sh": 'docker exec "$NAME" kadmin.local -q "getprinc x"\n',
        "b-gate.sh": 'docker exec "$NAME" \\\n    kadmin -p a -w b -q "addprinc y"\n',
        "c-gate.sh": ('docker exec "$NAME" kadmin.local listprincs | grep -q user\n# kadmin.local -q "x"\n'
                      'kadmin_q "addprinc z"\n'),
        "d-gate.sh": 'docker exec "$NAME" /tmp/krb5-kadmin-local -q "getprinc x"\n',
        "lib/e.sh": 'kadmin.local -q "x"\n',
        "capaths-transit-gate.sh": ('docker exec -i "$NAME" bash <<EOF\nkad() {\n    kadmin.local -r "\\$2" -q "\\$*"\n}\n'
                                    'EOF\nkadmin.local -q "outside"\n'),
    }
    check_kadmin_q_via_lib(kq_files, allow=4)
    _must_die_msg("5 direct kadmin queries", check_kadmin_q_via_lib, {**kq_files, "f-gate.sh": 'kadmin.local -q "x"\n'},
                  allow=4)
