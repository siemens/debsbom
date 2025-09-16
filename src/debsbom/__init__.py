# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

# Optional transitive dependency of dep822 which is only distributed
# via Debian (not pip). If not available but requested, the library
# issues a warning which we want to avoid by checking upfront and
# explicitly requesting the fallback mechanism.
try:
    import apt

    HAS_PYTHON_APT = True
except ImportError:
    HAS_PYTHON_APT = False
