#!/usr/bin/env python3
"""Verify a prepared fuzz build against its own content manifests.

    python3 scripts/security-fuzz-verify.py --build-dir ABS [--repo DIR]

`scripts/security-fuzz-build.sh` records a repository-relative, sorted source
manifest, a build-relative, sorted target manifest, and a `build.json` binding
those digests to the toolchain, the pinned oracle and the shipped artifact.
This verifier recomputes every one of those identities from the consumer's
current checkout and dev shell before a target may run:

  * the named build inputs and the generated Lean C sources, by content;
  * the shipped `.lake/build/lib/liblexpat.so.1` linked by `artifact-fuzz`;
  * the Clang and Lean executables, by path, version and content;
  * the pinned libexpat, by pkg-config version, library path and content;
  * each of the six named targets, by canonical relative path, regular-file
    kind, ELF class and SHA-256.

A missing, malformed, stale or mismatched manifest is refused with a distinct
message naming the failed identity. A target that is a symlink, or whose
resolved path leaves the build directory, is refused even when its bytes match
the recorded hash.

`--repo` names the checkout to verify against and defaults to this script's
repository; the validation controls use it to point at an isolated copy.
"""

import argparse
import hashlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys

REQUIRED_FORMAT = 2

NAMED_INPUTS = [
    "LexPat.lean",
    "tests/FuzzParser.lean",
    "lakefile.lean",
    "lake-manifest.json",
    "lean-toolchain",
    "flake.nix",
    "flake.lock",
    "cabi/expat.c",
    "cabi/exports.map",
    "include/expat.h",
    "tests/security/parser-fuzz.c",
    "tests/security/cabi-fuzz.c",
    "tests/security/differential.c",
    "scripts/security-fuzz-build.sh",
    ".lake/build/lib/liblexpat.so.1",
]

TARGETS = [
    ("parser-fuzz", "executable"),
    ("cabi-fuzz", "executable"),
    ("artifact-fuzz", "executable"),
    ("differential-fuzz", "executable"),
    ("differential-replay", "executable"),
    ("liblexpat-diff.so", "shared"),
]

HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Refusal(Exception):
    def __init__(self, message):
        super().__init__(message)


def refuse(message):
    raise Refusal(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_relpath(name, what):
    """A manifest path is canonical, relative and has no traversal segment."""
    if not name or name != name.strip():
        refuse(f"{what}: malformed path entry {name!r}")
    if name.startswith("/") or "\\" in name:
        refuse(f"{what}: path is not canonical: {name}")
    segments = name.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        refuse(f"{what}: path is not canonical: {name}")
    return name


def read_manifest(path, what):
    if not path.is_file():
        refuse(f"missing {what}: {path}")
    entries = {}
    previous = None
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            refuse(f"malformed {what}: blank line {lineno}")
        if len(line) < 67 or line[64:66] != "  ":
            refuse(f"malformed {what}: line {lineno} is not '<sha256>  <path>'")
        digest, name = line[:64], line[66:]
        if not HEX64.match(digest):
            refuse(f"malformed {what}: line {lineno} digest is not SHA-256")
        check_relpath(name, what)
        if previous is not None and name <= previous:
            refuse(f"malformed {what}: entries are not sorted and unique at {name}")
        previous = name
        entries[name] = digest
    if not entries:
        refuse(f"malformed {what}: no entries")
    return entries


def check_regular(path, base, what, name):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        refuse(f"missing {what}: {name}")
    if stat.S_ISLNK(info.st_mode):
        refuse(f"{what} is not a regular file: {name}")
    if not stat.S_ISREG(info.st_mode):
        refuse(f"{what} is not a regular file: {name}")
    resolved = os.path.realpath(path)
    root = os.path.realpath(base)
    if resolved != root and not resolved.startswith(root + os.sep):
        refuse(f"{what} escapes {root}: {name}")


def elf_kind(path):
    """'executable' when the ELF carries a PT_INTERP, 'shared' for a plain DYN."""
    with open(path, "rb") as f:
        header = f.read(64)
        if len(header) < 64 or header[:4] != b"\x7fELF":
            return "other"
        if header[4] != 2 or header[5] != 1:
            return "other"
        e_type = int.from_bytes(header[16:18], "little")
        e_phoff = int.from_bytes(header[32:40], "little")
        e_phentsize = int.from_bytes(header[54:56], "little")
        e_phnum = int.from_bytes(header[56:58], "little")
        if e_phentsize < 56 or e_phnum == 0:
            return "other"
        f.seek(e_phoff)
        table = f.read(e_phentsize * e_phnum)
    for index in range(e_phnum):
        offset = index * e_phentsize
        if int.from_bytes(table[offset:offset + 4], "little") == 3:
            return "executable"
    return "shared" if e_type == 3 else "other"


def expected_sources(repo):
    paths = set(NAMED_INPUTS)
    lexpat = repo / "LexPat"
    if not lexpat.is_dir():
        refuse(f"checkout has no LexPat directory: {repo}")
    for path in lexpat.rglob("*.lean"):
        paths.add(str(path.relative_to(repo)))
    ir = repo / ".lake" / "build" / "ir"
    paths.add(".lake/build/ir/LexPat.c")
    paths.add(".lake/build/ir/tests/FuzzParser.c")
    if not ir.is_dir():
        refuse(f"checkout has no generated Lean C sources: {ir}")
    for path in (ir / "LexPat").rglob("*.c"):
        relative = path.relative_to(repo)
        # The build links the library modules only; generated code for the
        # executables under `Exe/` is not a build input.
        if "Exe" in relative.parts:
            continue
        paths.add(str(relative))
    return paths


def command_first_line(argv):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                check=False)
    except OSError as exc:
        refuse(f"toolchain unavailable: {exc}")
    text = result.stdout.decode("utf-8", "replace").splitlines()
    return text[0] if text else ""


def pkg_config(*args):
    try:
        result = subprocess.run(["pkg-config", *args], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        refuse(f"pkg-config unavailable: {exc}")
    if result.returncode != 0:
        refuse("oracle identity unavailable: pkg-config failed")
    return result.stdout.decode("utf-8").strip()


def verify(build_dir, repo):
    build_dir = pathlib.Path(build_dir)
    repo = pathlib.Path(repo)
    if not build_dir.is_absolute():
        refuse(f"--build-dir must be absolute: {build_dir}")
    if not build_dir.is_dir():
        refuse(f"missing build directory: {build_dir}")
    build_file = build_dir / "build.json"
    if not build_file.is_file():
        refuse(f"missing build.json: {build_file}")
    try:
        import json

        build = json.loads(build_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        refuse(f"malformed build.json: {exc}")
    if not isinstance(build, dict):
        refuse("malformed build.json: not an object")
    if build.get("format") != REQUIRED_FORMAT:
        refuse(f"unsupported build.json format: {build.get('format')!r}")

    repo = repo.resolve()

    # ---- sources: exact set, then content ---------------------------------
    source_manifest = build_dir / str(build.get("source_manifest", ""))
    sources = read_manifest(source_manifest, "source manifest")
    recorded = build.get("source_manifest_sha256")
    if not isinstance(recorded, str) or not HEX64.match(recorded):
        refuse("malformed build.json: source_manifest_sha256")
    if sha256_file(source_manifest) != recorded:
        refuse("source manifest digest does not match build.json")

    expected = expected_sources(repo)
    actual = set(sources)
    if expected - actual:
        refuse("source set does not match the build inputs: missing "
               + ", ".join(sorted(expected - actual)[:3]))
    if actual - expected:
        refuse("source set does not match the build inputs: unexpected "
               + ", ".join(sorted(actual - expected)[:3]))

    for name in sorted(sources):
        path = repo / name
        check_regular(path, repo, "source path", name)
        if sha256_file(path) != sources[name]:
            refuse(f"source content mismatch: {name}")

    # ---- toolchain --------------------------------------------------------
    toolchain = build.get("toolchain")
    if not isinstance(toolchain, dict):
        refuse("malformed build.json: toolchain")
    clang_path = os.environ.get("CLANG") or shutil.which("clang")
    lean_path = shutil.which("lean")
    for label, path, argv in (
        ("clang", clang_path, [clang_path or "clang", "--version"]),
        ("lean", lean_path, [lean_path or "lean", "--version"]),
    ):
        record = toolchain.get(label)
        if not isinstance(record, dict):
            refuse(f"malformed build.json: toolchain.{label}")
        if path is None:
            refuse(f"toolchain unavailable: {label}")
        real = os.path.realpath(path)
        if os.path.realpath(str(record.get("path", ""))) != real:
            refuse(f"toolchain path mismatch: {label}")
        if record.get("version") != command_first_line(argv):
            refuse(f"toolchain version mismatch: {label}")
        if record.get("sha256") != sha256_file(real):
            refuse(f"toolchain content mismatch: {label}")

    # ---- oracle -----------------------------------------------------------
    oracle = build.get("oracle")
    if not isinstance(oracle, dict):
        refuse("malformed build.json: oracle")
    version = pkg_config("--modversion", "expat")
    if version != oracle.get("pkg_config_version"):
        refuse(f"oracle version mismatch: pkg-config says {version}")
    if oracle.get("version") != f"expat_{version}" or oracle.get("version_info") != version:
        refuse("oracle version mismatch: recorded version triple")
    oracle_path = os.path.join(pkg_config("--variable=libdir", "expat"), "libexpat.so.1")
    if os.path.realpath(str(oracle.get("path", ""))) != os.path.realpath(oracle_path):
        refuse("oracle library path mismatch")
    if not os.path.isfile(oracle_path):
        refuse(f"oracle library missing: {oracle_path}")
    if oracle.get("sha256") != sha256_file(oracle_path):
        refuse("oracle library content mismatch")

    # ---- shipped artifact -------------------------------------------------
    shipped = build.get("shipped_artifact")
    if not isinstance(shipped, dict):
        refuse("malformed build.json: shipped_artifact")
    shipped_name = check_relpath(str(shipped.get("path", "")), "build.json")
    shipped_path = repo / shipped_name
    check_regular(shipped_path, repo, "shipped artifact", shipped_name)
    if shipped.get("sha256") != sha256_file(shipped_path):
        refuse(f"shipped artifact content mismatch: {shipped_name}")

    # ---- targets ----------------------------------------------------------
    target_manifest = build_dir / str(build.get("targets_manifest", ""))
    targets = read_manifest(target_manifest, "target manifest")
    recorded_targets = build.get("targets")
    if not isinstance(recorded_targets, list):
        refuse("malformed build.json: targets")
    expected_targets = {name: kind for name, kind in TARGETS}
    if set(targets) != set(expected_targets):
        refuse("target set does not match the named targets")
    recorded_by_name = {}
    for entry in recorded_targets:
        if not isinstance(entry, dict) or entry.get("name") not in expected_targets:
            refuse("malformed build.json: targets entry")
        recorded_by_name[entry["name"]] = entry
    if set(recorded_by_name) != set(expected_targets):
        refuse("target set does not match the named targets")

    recorded_digest = build.get("targets_manifest_sha256")
    if not isinstance(recorded_digest, str) or not HEX64.match(recorded_digest):
        refuse("malformed build.json: targets_manifest_sha256")
    if sha256_file(target_manifest) != recorded_digest:
        refuse("target manifest digest does not match build.json")

    for name, kind in TARGETS:
        path = build_dir / name
        check_regular(path, build_dir, "target", name)
        if elf_kind(path) != kind:
            refuse(f"target kind mismatch: {name}")
        if sha256_file(path) != targets[name]:
            refuse(f"target content mismatch: {name}")
        entry = recorded_by_name[name]
        if entry.get("sha256") != targets[name] or entry.get("kind") != kind:
            refuse(f"build.json target record mismatch: {name}")

    # ---- revision (only when the checkout is a git worktree) --------------
    revision = build.get("revision")
    if not isinstance(revision, str) or not re.match(r"^[0-9a-f]{40,64}$", revision):
        refuse("malformed build.json: revision")
    if (repo / ".git").exists():
        head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              check=False)
        if head.returncode != 0:
            refuse("revision identity unavailable: git rev-parse failed")
        if head.stdout.decode().strip() != revision:
            refuse("revision mismatch: build was prepared on another commit")
    return len(sources), len(TARGETS)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build-dir", required=True)
    ap.add_argument("--repo", default=str(pathlib.Path(__file__).resolve().parent.parent))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    try:
        sources, targets = verify(args.build_dir, args.repo)
    except Refusal as exc:
        print(f"security-fuzz-verify: {exc}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"security-fuzz-verify: ok: {sources} hashed inputs, {targets} "
              f"hashed targets, toolchain and oracle identities match")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
