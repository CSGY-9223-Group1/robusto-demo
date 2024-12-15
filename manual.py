"""
A TUF repository example using the low-level TUF Metadata API.

NOTE: Metadata files will be written to a 'tmp*'-directory in CWD.

"""

from __future__ import annotations

import contextlib
import glob
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from securesystemslib.signer import CryptoSigner, Signer

from tuf.api.metadata import (
    SPECIFICATION_VERSION,
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer


def _in(days: float) -> datetime:
    """Adds 'days' to now and returns datetime object w/o microseconds."""
    return datetime.now(timezone.utc).replace(microsecond=0) + timedelta(
        days=days
    )

SPEC_VERSION = ".".join(SPECIFICATION_VERSION)

PRETTY = JSONSerializer(compact=False)
TMP_DIR = "manual-metadata"
os.makedirs(TMP_DIR, exist_ok=True)

# Define containers for role objects and cryptographic keys created below. This
# allows us to sign and write metadata in a batch more easily.
roles: dict[str, Metadata] = {}
signers: dict[str, Signer] = {}

# 1. Write "root.json".

# Root (root of trust)

# Create root metadata object
roles["root"] = Metadata(Root(expires=_in(365)))

online_key = CryptoSigner.generate_ecdsa()
offline_key = CryptoSigner.generate_ecdsa()

# Timestamp and snapshot reuse an online key
for name in ["timestamp", "snapshot"]:
    roles["root"].signed.add_key(online_key.public_key, name)

# Root and targets reuse an offline key
for name in ["root", "targets"]:
    roles["root"].signed.add_key(offline_key.public_key, name)

# Consistent snapshots
# How to safely write new metadata and targets w/o disrupting current readers
# Metadata: you write not only {rolename}.json, but also {version}.{rolename}.json
# Targets: you write not only {package}.{ext}, but also {hash}.{package}.{ext}

# Turn off consistent snapshots for now.
roles["root"].signed.consistent_snapshot = False

# Writing the root
# filename = f"{roles[name].signed.version}.{roles[name].signed.type}.json"
unversioned_root_filename = "root.json"
unversioned_root_path = os.path.join(TMP_DIR, unversioned_root_filename)
roles["root"].to_file(unversioned_root_path, serializer=PRETTY)

# Signing the root
root = Metadata.from_file(unversioned_root_path)
root.sign(offline_key)
root.to_file(unversioned_root_path, serializer=PRETTY)

# Write the consistent snapshot.
#versioned_root_filename = f'{roles["root"].signed.version}.{unversioned_root_filename}'
#versioned_root_path = os.path.join("TMP_DIR", versioned_root_filename)
#with contextlib.chdir(TMP_DIR):
#    os.symlink(unversioned_root_filename, versioned_root_filename)

# 2. Write the "packages-and-in-toto-metadata-signer.json".

TARGETS_DIR = "targets-ite2/"
targets = {}
package_custom_in_toto = ["in-toto-metadata/root.layout"]

# Just the in-toto links.
for disk_filename in glob.glob(f"{TARGETS_DIR}/in-toto-metadata/b4df3c864becf593a939414e5cfb85a7d9406b5f8bb645d248a35163c9afd3f9/*.link"):
    # TODO: write more robust code!
    metadata_filename = '/'.join(disk_filename.split('/')[1:]).lstrip('/')

    fileinfo = TargetFile.from_file(metadata_filename, disk_filename)
    targets[metadata_filename] = fileinfo

    package_custom_in_toto.append(metadata_filename)

# Now read the package.
metadata_filename = "packages/demo-project.tar.gz"
package_filename = os.path.join(TARGETS_DIR, metadata_filename)
package_fileinfo = TargetFile.from_file(metadata_filename, disk_filename)
targets[metadata_filename] = package_fileinfo
package_custom_in_toto.append
package_fileinfo.unrecognized_fields =  {
    "custom": {
        "in-toto": sorted(package_custom_in_toto)
    }
}

delegatee_name = "packages-and-in-toto-metadata-signer"
roles[delegatee_name] = Metadata[Targets](
    signed=Targets(
        version=1,
        spec_version=SPEC_VERSION,
        expires=_in(7),
        targets=targets,
    ),
    signatures={},
)

unversioned_delegatee_filename = f"{delegatee_name}.json"
unversioned_delegatee_path = os.path.join(TMP_DIR, unversioned_delegatee_filename)
roles[delegatee_name].to_file(unversioned_delegatee_path, serializer=PRETTY)

# Signing the delegatee
delegatee = Metadata.from_file(unversioned_delegatee_path)
delegatee.sign(online_key)
delegatee.to_file(unversioned_delegatee_path, serializer=PRETTY)
