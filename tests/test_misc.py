# Copyright (C) 2026 Siemens
#
# SPDX-License-Identifier: MIT

from debsbom.util.omnibor import artifact_id
from debsbom.util.swh import swh_id
from pathlib import Path


def test_artifact_id():
    artifact = Path("tests/data/artifact.txt")

    aid = artifact_id(artifact)
    assert (
        aid
        # reference created with omnibor-rs
        == "gitoid:blob:sha256:cb16a7604bae14bc2d888df559984c2c60920a65c8f4645a7583aa0f1dee8341"
    )


def test_swhid():
    artifact = Path("tests/data/artifact.txt")

    artifact_id = swh_id(artifact)
    assert artifact_id == "swh:1:cnt:4431b185ad78f191f7002a1756538aaa4fe12908"
