# Copyright (C) 2025 Siemens
#
# SPDX-License-Identifier: MIT

import os
import sys
import importlib.metadata as _metadata

# Insert the project root (two levels up) and the src folder.
# Fixed mismatched parentheses.
sys.path.insert(
    0,
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "src")),
)

import debsbom

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = "debsbom"
copyright = "2025, Siemens"
author = "Christoph Steiger"

# Derive the version from the installed package metadata.
# If the package is not installed, fall back to a placeholder.
try:
    release = _metadata.version("debsbom")
except _metadata.PackageNotFoundError:
    release = "0.0.0"  # fallback for development builds

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",  # pull doc‑strings from code
    "sphinx.ext.autodoc.typehints",  # optional, if you installed sphinx-autodoc-typehints
    "sphinx.ext.intersphinx",  # link to Python, etc.
    "sphinx.ext.viewcode",  # “[source]” links
    "sphinxarg.ext",  # argparse
]

templates_path = ["_templates"]
exclude_patterns = []

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = "sphinx_rtd_theme"
# If you want to customize:
# html_theme_options = {
#     "logo_only": True,
#     "display_version": True,
# }

html_static_path = ["_static"]
