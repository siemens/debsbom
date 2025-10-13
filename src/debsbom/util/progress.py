# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import sys


def progress_cb(i: int, n: int, name: str):
    clear = "\r\033[K"
    sys.stdout.write(f"{clear}processing {i+1}/{n} ({name})")
    if i + 1 == n:
        sys.stdout.write("\n")
    sys.stdout.flush()
