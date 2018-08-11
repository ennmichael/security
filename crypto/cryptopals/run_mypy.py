#!/usr/bin/env python3.7


from __future__ import annotations
import os
import functools


def run_mypy(filename: str) -> None:
    os.system(f'python3 -m mypy --disallow-untyped-defs --ignore-missing-imports {filename}')

