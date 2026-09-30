#!/usr/bin/env python3
"""Size and debt budget, enforced in CI (DESIGN.md N3, CLAUDE.md).

Fails when:
  * any Rust source file has more than FILE_LINES non-test lines (a god file);
  * the crates together have more than TOTAL_LINES non-test lines;
  * the crates declare more than DIRECT_DEPS direct dependencies;
  * any source file carries a TODO/FIXME/XXX/HACK marker. Debt is recorded in
    docs/HANDOFF.md where the maintainer sees it, not left in the code.

Non-test lines are those before the first `#[cfg(test)]`. Integration tests
under tests/ are not counted. Run: python3 scripts/check_size.py [repo root]
"""
import re
import sys
from pathlib import Path

FILE_LINES = 400
TOTAL_LINES = 4000
DIRECT_DEPS = 15
MARKER = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")


def non_test_lines(path: Path) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "#[cfg(test)]":
            return i
    return len(lines)


def direct_deps(cargo_toml: Path) -> set[str]:
    deps, section = set(), None
    for line in cargo_toml.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith("["):
            section = s
            continue
        # [dependencies] and [dependencies.<name>] tables count; dev-dependencies do not.
        if section == "[dependencies]" and s and not s.startswith("#"):
            deps.add(s.split("=")[0].strip())
        elif section and section.startswith("[dependencies."):
            deps.add(section[len("[dependencies."):-1])
    deps.discard("witness-core")  # our own crate
    return deps


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    problems = []

    total = 0
    for rs in sorted((root / "crates").rglob("*.rs")):
        if "target" in rs.parts or "tests" in rs.parts:
            continue
        n = non_test_lines(rs)
        total += n
        if n > FILE_LINES:
            problems.append(f"{rs.relative_to(root)}: {n} non-test lines, limit {FILE_LINES}; split it")
    if total > TOTAL_LINES:
        problems.append(f"crates total {total} non-test lines, limit {TOTAL_LINES}")

    deps = set()
    for toml in (root / "crates").glob("*/Cargo.toml"):
        deps |= direct_deps(toml)
    if len(deps) > DIRECT_DEPS:
        problems.append(f"{len(deps)} direct dependencies, limit {DIRECT_DEPS}: {sorted(deps)}")

    for src in list((root / "crates").rglob("*.rs")) + list((root / "scripts").glob("*")):
        if "target" in src.parts or not src.is_file() or src.name == Path(__file__).name:
            continue  # this file names the markers in order to look for them
        for i, line in enumerate(src.read_text(encoding="utf-8").splitlines(), 1):
            if MARKER.search(line):
                problems.append(f"{src.relative_to(root)}:{i}: debt marker; record it in docs/HANDOFF.md instead")

    print(f"crates: {total} non-test lines (limit {TOTAL_LINES}); {len(deps)} direct dependencies (limit {DIRECT_DEPS})")
    for p in problems:
        print(f"FAIL {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
