"""The self-test of the MIT-anchor and process-tag checks."""

from __future__ import annotations

import pathlib
import subprocess
import tempfile

from ..comments import (
    _check_ambiguous_pin, check_mit_anchor_form, check_mit_anchor_truth, check_no_docs_process_tags,
    check_no_process_history, mit_anchor_truth_violations,
)
from ..common import _die, _scratch_root
from .common import _must_die_msg


def _self_test_comments() -> None:
    anchor_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        src = anchor_root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        tests_dir = anchor_root / "crates" / "demo" / "tests"
        tests_dir.mkdir(parents=True)
        good = src / "lib.rs"
        in_tests = tests_dir / "t.rs"
        in_tests.write_text("", encoding="utf-8")
        accepted = {
            "fn-anchor": "/// MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "line-comment": "// MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "inner-doc": "//! MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay\n",
            "block": "/* MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay */\n",
            "header-anchor": "/// MIT `krb5_get_init_creds_opt` (`krb5.hin:6839-6851`): the option block\n",
            "et-anchor": "/// MIT `KADM5_UNK_PRINC` (`kadm_err.et:54-54`): an unknown principal\n",
            "type-anchor": "/// MIT `struct extended_options` (`krb/gic_opt.c:19-32`): the option tail\n",
            "qualified-basename": "// MIT `init_realm` (`kdc/main.c:286-345`): the realm stanza wins\n",
            "mention": "/// MIT `KRB5_KDB_DISALLOW_TGT_BASED`.\n",
            "file-mention": "//! Context establishment (`init_sec_context.c`, `accept_sec_context.c`).\n",
            "file-and-mention": "/// MIT `pac.c` `MAX_BUFFERS`.\n",
            "bare-file-mention": "// The loop mirrors gic_pwd.c.\n",
            "anchor-and-mention": "/// MIT `f` (`a.c:1-2`): calls `g` in `b.c` first\n",
            "backtick-guarantee": "/// MIT `f` (`a.c:1-2`): `KDC_ERR_X` on a bad key\n",
            "x-anchor": "/// MIT `kdb_incr_update_t` (`iprop.x:92-101`): one update\n",
            "y-anchor": "/// MIT `yyparse` (`getdate.y:210-240`): a date\n",
            "inner-doc-block": "/*! MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay */\n",
            "nested-block": "/* outer /* MIT `krb5_rd_req` (`rd_req.c:10-20`): refuses a replay */ still outer */\n",
        }
        for body in accepted.values():
            good.write_text(body, encoding="utf-8")
            check_mit_anchor_form(anchor_root, allow=0)
        good.write_text("", encoding="utf-8")
        in_tests.write_text(accepted["fn-anchor"], encoding="utf-8")
        check_mit_anchor_form(anchor_root, allow=0)
        in_tests.write_text("", encoding="utf-8")
        rejected = {
            "file-range-only": "/// (`do_as_req.c:10-20`)\n",
            "name-and-range": "/// MIT `krb5_rd_req` (`do_as_req.c:10-20`)\n",
            "file-point-only": "/// (`do_as_req.c:10`)\n",
            "bare-file": "/// MIT do_as_req.c:10 sets the flag\n",
            "name-and-point": "/// MIT `krb5_rd_req` (`do_as_req.c:10`)\n",
            "mit-backtick-point": "/// MIT `do_as_req.c:10` sets the flag\n",
            "prose-range": "// the check at do_tgs_req.c:10-20 runs first\n",
            "header-point": "// the rock (`kdc_util.h:422`)\n",
            "hin-range": "/// the option block (krb5.hin:6839-6851)\n",
            "et-point": "/// `kadm_err.et:54` names it\n",
            "multi-range": "/// (`server_stubs.c:478,519`)\n",
            "leftover-beside-anchor": "/// MIT `f` (`a.c:1-2`): checks first, see b.c:3\n",
            "two-anchors": "/// MIT `f` (`a.c:1-2`): x; MIT `g` (`b.c:3-4`): y\n",
            "no-guarantee": "/// MIT `f` (`a.c:1-2`):\n",
            "empty-guarantee": "/// MIT `f` (`a.c:1-2`): \n",
            "punct-guarantee": "/// MIT `stub_setup` (`server_stubs.c:296-301`): -638).\n",
            "paren-guarantee": "/// MIT `f` (`a.c:1-2`): (`g`,.\n",
            "same-check": "/// MIT `f` (`a.c:1-2`): same check.\n",
            "mit-guarantee": "/// MIT `f` (`a.c:1-2`): MIT.\n",
            "name-guarantee": "/// MIT `strdur` (`kadmin.c:118-138`): strdur.\n",
            "ambiguous-anchor": "// MIT `init_realm` (`main.c:286-345`): the realm stanza wins\n",
            "ambiguous-mention": "//! Principal names (`str_conv.c`).\n",
            "block-cite": "/* see do_as_req.c:10 */\n",
            "doc-block-cite": "/**\n * the check (`do_as_req.c:10-20`)\n */\n",
            "inner-doc-cite": "//! the check (`do_as_req.c:10-20`)\n",
            "line-comment-cite": "// the check (`do_as_req.c:10-20`)\n",
            "x-point": "/// `iprop.x:92` names it\n",
            "y-range": "// the rule at getdate.y:210-240 runs first\n",
            "inner-doc-block-cite": "/*! see do_as_req.c:10 */\n",
            "nested-block-cite": "/* outer /* see do_as_req.c:10 */ still outer */\n",
        }
        for shape, body in rejected.items():
            good.write_text(body, encoding="utf-8")
            _must_die_msg(
                "mit anchor lines 1 != allow 0",
                check_mit_anchor_form,
                anchor_root,
                allow=0,
            )
        good.write_text("", encoding="utf-8")
        in_tests.write_text(rejected["file-range-only"], encoding="utf-8")
        _must_die_msg(
            "mit anchor lines 1 != allow 0", check_mit_anchor_form, anchor_root, allow=0
        )
        check_mit_anchor_form(anchor_root, allow=1)
        _must_die_msg(
            "mit anchor lines 1 != allow 2",
            check_mit_anchor_form,
            anchor_root,
            allow=2,
        )
        # The shape names are part of the fixture, so a deleted shape is a
        # missing key, not a silent pass.
        if len(accepted) != 18 or len(rejected) != 30:
            _die("mit anchor fixtures dropped a shape")
    finally:
        subprocess.run(["rm", "-rf", str(anchor_root)], check=False)

    truth_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        fake = truth_root / "mit"
        for rel, text in {
            "lib/krb5/krb/gic_pwd.c": (
                "/* a file comment */\n\nstatic int\nhelper(int x)\n{\n    return callee(x);\n}\n\n"
                "/*\n * The password loop.\n */\nkrb5_error_code\n"
                "krb5_get_init_creds_password(int a)\n{\n    int r = helper(a);\n"
                "    if (isflagset(a, 1))\n        r = 1;\n    return r;\n}\n\n"
                "static const char *names[] = {\n    \"a\",\n};\n\nDEFFIELD(error_7, x, 7);\n"
            ),
            "include/k5-int.h": (
                "#define isflagset(flags, flag) \\\n    ((flags) & (flag))\n"
                "struct opt_tail {\n    int x;\n};\ntypedef struct {\n    int y;\n} opt_head;\n"
            ),
            "lib/kadm5/t_kadm5.c": "static void\nkinit(int x)\n{\n}\n",
            "kdc/main.c": "static void\ninit_realm(void)\n{\n}\n",
            "clients/ksu/main.c": "static void\ninit_realm(void)\n{\n}\n",
            "lib/kadm5/kadm_err.et": (
                "error_table ovk\nerror_code KADM5_FAILURE, \"Operation failed\"\n"
                "error_code KADM5_AUTH_GET, \"No get permission\"\n"
            ),
            "kdc/fast_util.c": (
                "static krb5_error_code armor_ap_request\n(struct state *s)\n{\n"
                "    return 0;\n}\n"
            ),
            "include/k5-inline.h": (
                "/* Verify a key. */\nstatic inline int\nverify_key(int k)\n{\n    return k;\n}\n"
            ),
            "include/plugin.h": (
                "/* The handle method. */\ntypedef int\n(*handle_fn)(int context,\n"
                "                int flags);\n"
            ),
            "lib/kadm5/internal.h": (
                "typedef struct _handle_t {\n    int magic;\n} handle_rec, *handle_t;\n"
            ),
            "include/iprop.h": (
                "struct kdb_last_t {\n    int sno;\n};\ntypedef struct kdb_last_t kdb_last_t;\n"
            ),
            "lib/krb5/asn.1/asn1_k_encode.c": (
                "/*\n * SecureCookie ::= SEQUENCE {\n *     time INTEGER\n * }\n */\n"
                "DEFSEQTYPE(secure_cookie, krb5_secure_cookie, fields);\n"
            ),
        }.items():
            (fake / rel).parent.mkdir(parents=True, exist_ok=True)
            (fake / rel).write_text(text, encoding="utf-8")
        crate_src = truth_root / "crates" / "demo" / "src"
        crate_tests = truth_root / "crates" / "demo" / "tests"
        crate_src.mkdir(parents=True)
        crate_tests.mkdir(parents=True)

        def truth(body: str, in_tests: bool = False) -> int:
            (crate_src / "lib.rs").write_text("" if in_tests else body, encoding="utf-8")
            (crate_tests / "t.rs").write_text(body if in_tests else "", encoding="utf-8")
            return len(mit_anchor_truth_violations(truth_root, fake))

        holds = {
            "fn-body": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:14-18`): loops\n",
            "doc-block": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:9-19`): documented\n",
            "slack": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:6-19`): slack\n",
            "type": "// MIT `struct opt_tail` (`k5-int.h:3-5`): the tail\n",
            "typedef-tail": "// MIT `opt_head` (`k5-int.h:6-8`): the head\n",
            "header-macro": "// MIT `isflagset` (`k5-int.h:1-2`): tests a flag\n",
            "data": "// MIT `names` (`gic_pwd.c:21-23`): the table\n",
            "macro-gen": "// MIT `error_7` (`gic_pwd.c:25-25`): the field\n",
            "errcode": "// MIT `KADM5_FAILURE` (`kadm_err.et:2-2`): unspecified\n",
            "qualified": "// MIT `init_realm` (`kdc/main.c:2-4`): realm first\n",
            "mention": "//! Mirrors `gic_pwd.c` and `kdc/main.c`.\n",
            "split-declarator": "// MIT `armor_ap_request` (`fast_util.c:3-5`): armor first\n",
            "static-inline": "// MIT `verify_key` (`k5-inline.h:1-6`): the key check\n",
            "fn-pointer-typedef": "// MIT `handle_fn` (`plugin.h:1-4`): the method\n",
            "typedef-list-tail": "// MIT `handle_rec` (`internal.h:3-3`): the handle\n",
            "rpcgen-typedef": "// MIT `kdb_last_t` (`iprop.h:1-4`): the last entry\n",
            "asn1-comment": "// MIT `SecureCookie` (`asn1_k_encode.c:2-4`): the cookie\n",
        }
        for label, body in holds.items():
            if truth(body) != 0:
                _die(f"check_mit_anchor_truth must accept {label}: {mit_anchor_truth_violations(truth_root, fake)}")
        if truth("// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n", in_tests=True) != 0:
            _die("check_mit_anchor_truth must accept a test citing MIT test code")
        # src/tests.rs is a test file too: it may cite MIT test code.
        (crate_src / "tests.rs").write_text("// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n", encoding="utf-8")
        if truth("") != 0:
            _die(f"check_mit_anchor_truth must accept src/tests.rs citing MIT test code: "
                 f"{mit_anchor_truth_violations(truth_root, fake)}")
        (crate_src / "tests.rs").unlink()
        breaks = {
            "callee": "// MIT `callee` (`gic_pwd.c:6-6`): calls\n",
            "macro-slot": "// MIT `isflagset` (`gic_pwd.c:16-16`): tests\n",
            "wrong-fn": "// MIT `helper` (`gic_pwd.c:15-15`): helps\n",
            "lead-overhang": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:5-19`): early\n",
            "tail-overhang": "// MIT `krb5_get_init_creds_password` (`gic_pwd.c:14-20`): late\n",
            "test-from-src": "// MIT `kinit` (`t_kadm5.c:2-4`): a test ticket\n",
            "ambiguous": "// MIT `init_realm` (`main.c:2-4`): realm first\n",
            "unknown-file": "// MIT `f` (`nosuch.c:1-2`): gone\n",
            "mention-unknown": "//! Mirrors `nosuch.c`.\n",
            "mention-ambiguous": "//! Mirrors `main.c`.\n",
            "type-outside": "// MIT `struct opt_tail` (`k5-int.h:6-8`): the tail\n",
            "data-outside": "// MIT `names` (`gic_pwd.c:25-25`): the table\n",
            "macro-gen-outside": "// MIT `error_7` (`gic_pwd.c:21-23`): the field\n",
            "errcode-outside": "// MIT `KADM5_FAILURE` (`kadm_err.et:3-3`): unspecified\n",
            "asn1-outside": "// MIT `SecureCookie` (`asn1_k_encode.c:6-6`): the cookie\n",
            "path-boundary": "// MIT `init_realm` (`dc/main.c:2-4`): realm first\n",
        }
        for label, body in breaks.items():
            if truth(body) != 1:
                _die(f"check_mit_anchor_truth must flag {label} once: {mit_anchor_truth_violations(truth_root, fake)}")
        truth(breaks["callee"])
        check_mit_anchor_truth(truth_root, fake, allow=1)
        _must_die_msg("mit anchor truth 1 != allow 0", check_mit_anchor_truth, truth_root, fake, allow=0)
        _must_die_msg("_AMBIGUOUS_MIT_BASENAMES differs", _check_ambiguous_pin, fake)
        if len(holds) != 17 or len(breaks) != 16:
            _die("mit anchor truth fixtures dropped a case")
    finally:
        subprocess.run(["rm", "-rf", str(truth_root)], check=False)

    tag_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        src = tag_root / "crates" / "demo" / "src"
        src.mkdir(parents=True)
        good = src / "lib.rs"
        for body in (
            "// the parent principal stays\n",
            "/// the magic word `deadbeef` and `0x12345678`\n",
            "/// each item is checked; networking/ is not a path here\n",
            "/// a SHA-256 digest; B-frames; F-strings\n",
        ):
            good.write_text(body, encoding="utf-8")
            check_no_process_history(tag_root, allow=0)
        good.write_text('fn f() {\n    let s = "// R12 in a string";\n}\n', encoding="utf-8")
        check_no_process_history(tag_root, allow=0)
        tagged = {
            "R12": "// R12 left the suppression\n",
            "A-prime": "// A\u2032-3 item 14\n",
            "W0": "// W0e H7\n",
            "W1": "// W1-Z follow-up\n",
            "Round": "// Round 2\n",
            "parent": "// parent abcdef0\n",
            "R2-S3": "// limit (R2-S3).\n",
            "B3": "// referral (B3).\n",
            "Y0": "// the Y0 mismatch\n",
            "Z": "// before Z6.3 the wire code was 60\n",
            "sha": "//! the check landed in `59c363b`.\n",
            "parent-red": "//! the unit is (parent-red).\n",
            "compiles-at": "//! Compiles at the parent and fails there.\n",
            "item": "/// order stays item 15.\n",
            "S-section": "// Helpers moved here in S2.3.\n",
            "Z-leftover": "//! Z8 leftover: the stamp.\n",
            "B-F": "//! F4 hierarchical referral.\n",
            "the-parent": "//! at the parent `abcdef0` it fails.\n",
            "B-half": "//! B7 hierarchical referral.\n",
            "the-parent-name": "//! at the parent `main` it fails.\n",
            "fails-at": "//! fails at 1a2b3c4 without the fix.\n",
            "working": "//! see `working/logs/x.log`.\n",
        }
        for body in tagged.values():
            good.write_text(body, encoding="utf-8")
            _must_die_msg(
                "process-history lines 1 != allow 0",
                check_no_process_history,
                tag_root,
                allow=0,
            )
        good.write_text(tagged["B3"], encoding="utf-8")
        check_no_process_history(tag_root, allow=1)
        if len(tagged) != 22:
            _die("process-history fixtures dropped a tag")
    finally:
        subprocess.run(["rm", "-rf", str(tag_root)], check=False)
    # The docs arm of the process-tag check (lines with a tag, fenced code excluded), one line
    # per arm of the tag pattern, so a dropped arm changes the count.
    dt_root = pathlib.Path(tempfile.mkdtemp(dir=_scratch_root()))
    try:
        (dt_root / "docs").mkdir()
        (dt_root / "docs" / "x.md").write_text(
            "Plain text.\n| a | settled in W1-Z |\n```\nitem 4 in a fence\n```\nSee item 12.\nAs in Z7.1.\n"
            "Graded R2-D1 here.\nThe A\u2032-3 row.\nClosed in W3-S1.\nAfter W0d it moved.\nUnder Track B.\n"
            "The lab trust (A5).\nSince C2 the text differs.\nPromoted in W3.\n"
            "Reconciled in A2/A5.\nThe trust (post-E3, nightly).\nThe Batch D rows.\n"
            "Stage G4, Era III and section A2 are not tags.\nRevision D2.1, x/E3 and J45 are not labels.\n",
            encoding="utf-8",
        )
        check_no_docs_process_tags(dt_root, allow=14)
        _must_die_msg("14 docs line(s) with a process tag, allow 0", check_no_docs_process_tags, dt_root, allow=0)
        # A section cite quoting a gate's own tagged echo text, resolved in that gate, is not counted (the
        # temporary arm); the same text that does not resolve counts.
        (dt_root / "scripts").mkdir()
        (dt_root / "scripts" / "a-gate.sh").write_text('echo "==== Z7.1 omitted till ===="\n', encoding="utf-8")
        (dt_root / "docs" / "x.md").write_text("| r | `scripts/a-gate.sh` `==== Z7.1 omitted till ====` |\n",
                                               encoding="utf-8")
        check_no_docs_process_tags(dt_root, allow=0)
        (dt_root / "docs" / "x.md").write_text("| r | `scripts/a-gate.sh` `==== Z7.2 not there ====` |\n",
                                               encoding="utf-8")
        _must_die_msg("1 docs line(s) with a process tag, allow 0", check_no_docs_process_tags, dt_root, allow=0)
    finally:
        subprocess.run(["rm", "-rf", str(dt_root)], check=False)
