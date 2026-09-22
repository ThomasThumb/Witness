#!/usr/bin/env python3
"""Fail if any contact in rules/contacts.toml was last checked more than six
months ago. Dependency-free (tomllib is in the standard library from 3.11).
BUILD_PLAN.md phase 3, step 3."""
import datetime
import sys
import tomllib

MAX_AGE_MONTHS = 6


def months_since(yyyy_mm: str, today: datetime.date) -> int:
    y, m = (int(x) for x in yyyy_mm.split("-"))
    return (today.year - y) * 12 + (today.month - m)


def main(path: str) -> int:
    with open(path, "rb") as f:
        contacts = tomllib.load(f).get("contact", [])
    today = datetime.date.today()
    stale = []
    for c in contacts:
        checked = c.get("checked", "")
        try:
            age = months_since(checked, today)
        except ValueError:
            stale.append(f"{c.get('name')}: checked={checked!r} is not YYYY-MM")
            continue
        if age > MAX_AGE_MONTHS:
            stale.append(f"{c.get('name')}: last checked {checked} ({age} months ago)")
    for line in stale:
        print("STALE:", line)
    print(f"{len(contacts)} contacts, {len(stale)} stale")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "rules/contacts.toml"))
