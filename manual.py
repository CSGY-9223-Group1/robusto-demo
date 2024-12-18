"""
A TUF repository example using the low-level TUF Metadata API.

NOTE: Metadata files will be written to a 'tmp*'-directory in CWD.

"""

from __future__ import annotations

import contextlib
import glob
import json
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

# Helper function to reorder dictionaries with nested keys:
def sort_nested_dict(d):
    """Recursively sorts a nested dictionary by keys."""
    if isinstance(d, dict):
        return {k: sort_nested_dict(v) for k, v in sorted(d.items())}
    else:
        return d

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
unversioned_root_filename = "1.root.json"
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
        expires= _in(1),
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

# 3. Write the targets.json

# Convert roles["root"] to dictionary object so it's easier to work with
roles_dict = roles["root"].to_dict()
# Get offline key id
offline_key_id = roles_dict["signed"]["roles"]["root"]["keyids"][0]
# Get offline key
offline_public_key = roles_dict["signed"]["keys"][offline_key_id]["keyval"]["public"]

# # Create skeleton for targets file minus delegations and targets
roles["targets"] = Metadata[Targets](
    signed=Targets(
        spec_version=SPEC_VERSION,
        expires=_in(1),
        version=1,
    ),
)

# Create target dict for remaining key/values 
targets_dict = roles["targets"].to_dict()

# Create delegations
# First add the values for keys
targets_dict["signed"]["delegations"] = {"keys": {offline_key_id: {}}}
targets_dict["signed"]["delegations"]["keys"][offline_key_id] = {
    "keytype": "ecdsa",
    "keyval": {
        "public": offline_public_key
    },
    "scheme": "ecdsa-sha2-nistp256"
}
# Next add the values for roles
targets_dict["signed"]["delegations"]["roles"] = [
    {
        "keyids": [offline_key_id],
        "name": delegatee_name,
        "paths": ["in-toto-metadata/*/*.link", "packages/*"],
        "terminating": True,
        "threshold": 1
    }
]

# Create and add targets in dictionary object

targets_dict["signed"]["targets"] = {
    "in-toto-metadata/root.layout": {
        "custom": {
            "in-toto": ["in-toto-pubkeys/alice.pub"]
        },
        # Not sure where these come from? Might need to be updated
        "hashes": {
            "sha256": "fd638c9e085b8aea9394beaa960bb27e10a6cd2d2303bd690369bf90fd8ac0de"
        },
        "length": 5340 
    },
    "in-toto-pubkeys/alice.pub": {
        # Not sure where these come from? Might need to be updated
        "hashes": {
            "sha256": "06b6b81c16fce5a9a67494a01ab5a47fba9ce37f7432c88759f4ea98ea44328e"
        },
        "length": 625
    } 
}

# Create targets.json and do first write to it
unversioned_target_filename = "targets.json"
unversioned_target_path = os.path.join(TMP_DIR, unversioned_target_filename)
roles["targets"].to_file(unversioned_target_path, serializer=PRETTY)

# Load the targets file
targets = Metadata.from_file(unversioned_target_path)
# Add the signatures to it
targets.sign(offline_key)

# Once signatures are added, write to a dict for easier handling
sig_dict = targets.to_dict()

# Remove the signed key/values from sig_dict since we'll get them from targets_dict
del sig_dict["signed"]
# Remove the signatures key/values from targets_dict since we'll get them from sig_dict
del targets_dict["signatures"]

# Merge contents from both dicts into targets_dict
targets_dict.update(sig_dict)

# Recursively sort keys in target_dict so they are in alphabetic order
targets_dict_sorted = sort_nested_dict(targets_dict)

# Do final write of targets_dict to targets.json
with open(TMP_DIR + "/" + "targets.json", "w") as f:
    json.dump(targets_dict_sorted, f, indent=1)

# 4. Write the snapshot.json
roles["snapshot"] = Metadata(Snapshot(expires=_in(1)))

# Create snapshot.json and do first write to it
unversioned_snapshot_filename = "snapshot.json"
unversioned_snapshot_path = os.path.join(TMP_DIR, unversioned_snapshot_filename)
roles["snapshot"].to_file(unversioned_snapshot_path, serializer=PRETTY)

snapshots = Metadata.from_file(unversioned_snapshot_path)
snapshots.sign(online_key)

# Convert snapshots to dictionary object so it's easier to work with
snapshot_dict = snapshots.to_dict()

# Update meta key
snapshot_dict["signed"]["meta"] = {
    "packages-and-in-toto-metadata-signer.json": {
        "version": 1
    },
    "targets.json": {
        "version": 1
    }
}

# Recursively sort keys in target_dict so they are in alphabetic order
snapshot_dict_sorted = sort_nested_dict(snapshot_dict)

# Do final write of targets_dict to targets.json
with open(TMP_DIR + "/" + "snapshot.json", "w") as f:
    json.dump(snapshot_dict_sorted, f, indent=1)

# 5. Write the timestamp.json
roles["timestamp"] = Metadata(Timestamp(expires=_in(1)))

# Create timestamp.json and do first write to it
unversioned_timestamp_filename = "timestamp.json"
unversioned_timestamp_path = os.path.join(TMP_DIR, unversioned_timestamp_filename)
roles["timestamp"].to_file(unversioned_timestamp_path, serializer=PRETTY)

timestamps = Metadata.from_file(unversioned_timestamp_path)
timestamps.sign(online_key)
timestamps.to_file(unversioned_timestamp_path, serializer=PRETTY)