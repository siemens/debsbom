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
author = "Christoph Steiger, Felix Moessbauer"

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
exclude_patterns = ["man/man"]
if tags.has("man/man"):
    exclude_patterns.remove("man/man")

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

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
    ("man/debsbom", "debsbom", "a SBOM tool for Debian", [author], 1),
    ("man/debsbom-decisions", "debsbom-decisions", "debsbom design decisions", [author], 1),
    ("man/debsbom-download", "debsbom-download", "debsbom download command", [author], 1),
    ("man/debsbom-export", "debsbom-export", "debsbom export command", [author], 1),
    ("man/debsbom-generate", "debsbom-generate", "debsbom generate command", [author], 1),
    ("man/debsbom-merge", "debsbom-merge", "debsbom merge command", [author], 1),
    ("man/debsbom-repack", "debsbom-repack", "debsbom repack command", [author], 1),
    ("man/debsbom-delta", "debsbom-delta", "debsbom delta command", [author], 1),
    (
        "man/debsbom-source-merge",
        "debsbom-source-merge",
        "debsbom source-merge command",
        [author],
        1,
    ),
]
