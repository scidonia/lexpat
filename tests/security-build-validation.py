#!/usr/bin/env python3
"""Acceptance and rejection controls for a prepared fuzz build.

    python3 tests/security-build-validation.py --build-dir ABS

The prepared build is first accepted by `scripts/security-fuzz-verify.py`.
Every other control mutates an isolated copy of the build metadata, of the
manifest's checkout inputs, or of a named target, and requires the verifier to
refuse with the identity or path message that control targets -- never with a
manifest-format or missing-file failure standing in for the intended check.

Isolation uses hard links, so the prepared build and the checkout are never
modified: a mutated file is unlinked first and then written fresh.
"""

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
VERIFIER = REPO / "scripts" / "security-fuzz-verify.py"
BUILD_METADATA = ("build.json", "source-manifest.sha256", "targets.sha256")


class ControlFailed(Exception):
    pass


def check(condition, label, detail=""):
    if condition:
        print(f"PASS {label}")
        return 0
    print(f"FAIL {label}{': ' + detail if detail else ''}")
    raise ControlFailed(label)


def read_manifest(path):
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line[:64], line[66:]
        entries[name] = digest
    return entries


def hardlink_tree(paths, source_root, target_root):
    """Hard-link each relative path from source_root into target_root."""
    for name in paths:
        src = source_root / name
        dst = target_root / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        os.link(src, dst)


def copy_build(source, target):
    """Copy the metadata and hard-link the six named targets."""
    target.mkdir(parents=True, exist_ok=True)
    for name in BUILD_METADATA:
        shutil.copy2(source / name, target / name)
    targets = read_manifest(source / "targets.sha256")
    for name in targets:
        os.link(source / name, target / name)
    return targets


def rewrite(path, data):
    os.unlink(path)
    path.write_bytes(data)


def bump(path):
    original = path.read_bytes()
    rewrite(path, original + b"\n")


def verifier(build_dir, repo=None):
    argv = [sys.executable, str(VERIFIER), "--build-dir", str(build_dir), "--quiet"]
    if repo is not None:
        argv += ["--repo", str(repo)]
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False)
    return result.returncode, result.stderr.decode("utf-8", "replace").strip()


def expect_refusal(build_dir, label, needle, repo=None):
    code, message = verifier(build_dir, repo)
    check(code != 0, f"{label}: refused", f"verifier exited {code}")
    check(needle in message, f"{label}: refusal names {needle!r}",
          message or "(no message)")
    check(not message.startswith("malformed build.json") or needle.startswith("malformed"),
          f"{label}: reached the intended check", message)


def context(tmp, base_build, base_repo):
    """Fresh isolated build and checkout copies sharing hard links."""
    build = tmp / "build"
    repo = tmp / "repo"
    copy_build(base_build, build)
    sources = read_manifest(base_build / "source-manifest.sha256")
    hardlink_tree(sources, base_repo, repo)
    return build, repo, sources


def run_controls(base_build, base_repo):
    failures = 0
    with tempfile.TemporaryDirectory(prefix="lexpat-build-validation-") as tmpdir:
        tmp = pathlib.Path(tmpdir)

        # 1. The prepared build is accepted as it stands.
        code, message = verifier(base_build)
        if code == 0:
            print(f"PASS valid prepared build accepted (exit {code})")
        else:
            print(f"FAIL valid prepared build rejected: {message}")
            failures += 1

        def case(label, needle, mutate):
            nonlocal failures
            build, repo, sources = context(tmp / label, base_build, base_repo)
            try:
                repo_arg = mutate(build, repo, sources)
                expect_refusal(build, label, needle, repo_arg)
            except ControlFailed:
                failures += 1

        def drop_build(build, repo, sources):
            (build / "build.json").unlink()
            return repo

        def malformed_build(build, repo, sources):
            (build / "build.json").write_text("{", encoding="utf-8")
            return repo

        def drop_source_manifest(build, repo, sources):
            (build / "source-manifest.sha256").unlink()
            return repo

        def drop_target(build, repo, sources):
            (build / "cabi-fuzz").unlink()
            return repo

        def stale_source(build, repo, sources):
            name = sorted(n for n in sources if n.startswith("LexPat/"))[0]
            bump(repo / name)
            return repo

        def missing_generated(build, repo, sources):
            name = sorted(n for n in sources if n.startswith(".lake/build/ir/"))[0]
            (repo / name).unlink()
            return repo

        def stale_generated(build, repo, sources):
            name = sorted(n for n in sources if n.startswith(".lake/build/ir/"))[0]
            bump(repo / name)
            return repo

        def changed_shipped(build, repo, sources):
            shipped = ".lake/build/lib/liblexpat.so.1"
            bump(repo / shipped)
            # Keep the source manifest and its digest valid so the shipped
            # artifact check itself is the one that refuses.
            lines = (build / "source-manifest.sha256").read_text(encoding="utf-8").splitlines()
            import hashlib

            digest = hashlib.sha256((repo / shipped).read_bytes()).hexdigest()
            lines = [f"{digest}  {shipped}" if line.endswith("  " + shipped) else line
                     for line in lines]
            (build / "source-manifest.sha256").write_text("\n".join(lines) + "\n",
                                                          encoding="utf-8")
            build_json = json.loads((build / "build.json").read_text(encoding="utf-8"))
            build_json["source_manifest_sha256"] = hashlib.sha256(
                (build / "source-manifest.sha256").read_bytes()).hexdigest()
            (build / "build.json").write_text(json.dumps(build_json),
                                              encoding="utf-8")
            return repo

        def edit_build(mutate):
            def apply(build, repo, sources):
                data = json.loads((build / "build.json").read_text(encoding="utf-8"))
                mutate(data)
                (build / "build.json").write_text(json.dumps(data), encoding="utf-8")
                return None
            return apply

        def flipped_target(build, repo, sources):
            bump(build / "parser-fuzz")
            return None

        def symlink_escape(build, repo, sources):
            outside = tmp / "outside"
            outside.mkdir(exist_ok=True)
            destination = outside / "artifact-fuzz"
            shutil.move(str(build / "artifact-fuzz"), str(destination))
            os.symlink(destination, build / "artifact-fuzz")
            return None

        case("missing-build", "missing build.json", drop_build)
        case("malformed-build", "malformed build.json", malformed_build)
        case("missing-source-manifest", "missing source manifest", drop_source_manifest)
        case("missing-target", "missing target: cabi-fuzz", drop_target)
        case("stale-source", "source content mismatch: LexPat/", stale_source)
        case("missing-generated", "missing source path: .lake/build/ir/LexPat.c",
             missing_generated)
        case("stale-generated", "source content mismatch: .lake/build/ir/", stale_generated)
        case("changed-shipped", "shipped artifact content mismatch", changed_shipped)
        case("flipped-target", "target content mismatch: parser-fuzz", flipped_target)
        case("symlink-escape", "target is not a regular file: artifact-fuzz",
             symlink_escape)
        case("toolchain-content", "toolchain content mismatch: clang",
             edit_build(lambda data: data["toolchain"]["clang"].update(
                 {"sha256": "0" * 64})))
        case("toolchain-version", "toolchain version mismatch: lean",
             edit_build(lambda data: data["toolchain"]["lean"].update(
                 {"version": "Lean (version 0.0.0)"})))
        case("oracle-version", "oracle version mismatch",
             edit_build(lambda data: data["oracle"].update(
                 {"version": "expat_2.8.4"})))
        case("oracle-version-info", "oracle version mismatch",
             edit_build(lambda data: data["oracle"].update(
                 {"version_info": "2.8.4"})))
        case("oracle-path", "oracle library path mismatch",
             edit_build(lambda data: data["oracle"].update(
                 {"path": "/nonexistent/libexpat.so.1"})))
        case("oracle-content", "oracle library content mismatch",
             edit_build(lambda data: data["oracle"].update(
                 {"sha256": "0" * 64})))
        case("manifest-digest", "source manifest digest does not match build.json",
             edit_build(lambda data: data.update(
                 {"source_manifest_sha256": "0" * 64})))

    print(f"security-build-validation: {'PASS' if failures == 0 else 'FAIL'} "
          f"({failures} controls failed)")
    return 0 if failures == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--repo", default=str(REPO))
    args = ap.parse_args(argv)
    build = pathlib.Path(args.build_dir)
    repo = pathlib.Path(args.repo)
    if not build.is_absolute():
        print("security-build-validation: --build-dir must be absolute", file=sys.stderr)
        return 2
    if not (build / "build.json").is_file():
        print(f"security-build-validation: no prepared build at {build}", file=sys.stderr)
        return 2
    return run_controls(build, repo)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
