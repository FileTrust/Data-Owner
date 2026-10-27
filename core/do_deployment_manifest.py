"""A.0 deployment-manifest verification for the DO.

A running DO must be pinned to the exact contract stack it was configured for. This module
verifies the versioned deployment manifest (produced by
Blockchain/scripts/generate_deployment_manifest.js) against the DO's configured chain id
and contract addresses, mirroring the VK-side check. It has NO web3/GUI imports so it is
importable and unit-testable in isolation; the config-vs-manifest binding is checkable
without any RPC round-trip and fails closed on any mismatch or malformed manifest.
"""

from __future__ import annotations

import json


class DeploymentManifestError(Exception):
    """Raised when a deployment manifest is malformed or does not match the DO config."""


def load_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    if not isinstance(manifest, dict):
        raise DeploymentManifestError("manifest is not a JSON object")
    if manifest.get("manifestKind") != "filetrust-deployment-manifest":
        raise DeploymentManifestError(
            f"not a filetrust deployment manifest: kind={manifest.get('manifestKind')!r}"
        )
    return manifest


def _addr_eq(a: object, b: object) -> bool:
    return str(a or "").strip().lower() == str(b or "").strip().lower()


_REQUIRED_WIRING = [
    ("StorageProofSC", "partitionSnapshotProof", "PartitionSnapshotProofSC"),
    ("StorageProofSC", "capacityProof", "CapacityProofSC"),
    ("CapacityProofSC", "partitionSnapshotProof", "PartitionSnapshotProofSC"),
    ("CapacityProofSC", "storageProof", "StorageProofSC"),
    ("PartitionSnapshotProofSC", "storageProof", "StorageProofSC"),
    ("PartitionSnapshotProofSC", "capacityProof", "CapacityProofSC"),
    # G.1A: the capacity certification authority edge, required in both directions.
    ("CapacityProofSC", "certificationContract", "CapacityCertificationSC"),
    ("CapacityCertificationSC", "capacityProofSC", "CapacityProofSC"),
    # G.2A: exact incremental membership wiring, required in both directions.
    ("PartitionSnapshotProofSC", "incrementalBatch", "CapacityIncrementalBatchSC"),
    ("CapacityIncrementalBatchSC", "snapshotProof", "PartitionSnapshotProofSC"),
    ("CapacityIncrementalBatchSC", "capacityProof", "CapacityProofSC"),
    ("FileRegistrationSC", "deletionRelease", "DeletionReleaseSC"),
    ("PartitionSnapshotProofSC", "deletionRelease", "DeletionReleaseSC"),
    ("StorageProofSC", "deletionRelease", "DeletionReleaseSC"),
    ("DeletionReleaseSC", "fileRegistration", "FileRegistrationSC"),
    ("DeletionReleaseSC", "snapshotProof", "PartitionSnapshotProofSC"),
    ("DeletionReleaseSC", "storageProof", "StorageProofSC"),
]

_REQUIRED_CONTRACT_FIELDS = (
    "runtimeCodeHash", "abiHash", "deploymentBlock",
    "deploymentTransactionHash", "contractVersion",
)


def _entry_addr(entry: dict) -> str:
    return str(entry.get("contractAddress") or entry.get("address") or "")


def _entry_code_hash(entry: dict) -> str:
    return str(entry.get("runtimeCodeHash") or entry.get("codeHash") or "")


def verify_manifest(
    manifest: dict,
    *,
    chain_id: int,
    addresses: dict,
    fetch_code=None,
    fetch_wiring=None,
    local_abi_hash=None,
    deployed_addresses_hash: str | None = None,
    deployed_addresses_contracts: dict | None = None,
) -> None:
    """Verify the manifest against DO config and (optionally) the live chain.

    Args mirror the VK verifier. fetch_code(address)->hex, fetch_wiring(consumer,getter)->
    address, and local_abi_hash(name)->hex are optional injectable callables; when None the
    corresponding on-chain / ABI check is skipped (the manifest-internal + config checks
    always run). deployed_addresses_hash/contracts, when provided, are cross-checked.
    Raises DeploymentManifestError on any mismatch (fail closed).
    """
    if not str(manifest.get("schema") or "").strip():
        raise DeploymentManifestError("manifest missing schema identifier")
    if not str(manifest.get("deployedAddressesHash") or "").strip():
        raise DeploymentManifestError("manifest missing deployedAddressesHash")
    if str(manifest.get("chainId", "")).strip() != str(int(chain_id)):
        raise DeploymentManifestError(
            f"manifest chainId {manifest.get('chainId')} != configured chainId {chain_id}"
        )
    contracts = manifest.get("contracts") or {}
    if not isinstance(contracts, dict):
        raise DeploymentManifestError("manifest contracts is not an object")

    needed = {"PartitionSnapshotProofSC"}
    for name, configured in (addresses or {}).items():
        if configured:
            needed.add(name)

    for name in needed:
        entry = contracts.get(name)
        if not entry or not _entry_addr(entry):
            raise DeploymentManifestError(f"manifest is missing required contract {name}")
        for field in _REQUIRED_CONTRACT_FIELDS:
            if not str(entry.get(field) or "").strip():
                raise DeploymentManifestError(f"manifest contract {name} missing field {field}")
        configured = (addresses or {}).get(name)
        if configured and not _addr_eq(_entry_addr(entry), configured):
            raise DeploymentManifestError(
                f"manifest {name} address {_entry_addr(entry)} != configured {configured}"
            )

    # manifest-internal wiring invariant (always).
    wiring = manifest.get("wiring") or {}
    for consumer, getter, target in _REQUIRED_WIRING:
        if consumer not in needed:
            continue
        tgt = contracts.get(target)
        if not tgt:
            raise DeploymentManifestError(f"manifest wiring target {target} missing")
        edge = f"{consumer}.{getter}"
        got = wiring.get(edge)
        if got is None:
            raise DeploymentManifestError(f"manifest missing wiring edge {edge}")
        if not _addr_eq(got, _entry_addr(tgt)):
            raise DeploymentManifestError(
                f"manifest wiring {edge} {got} != {target} {_entry_addr(tgt)}"
            )

    # deployed_addresses.json hash + addresses.
    if deployed_addresses_hash is not None:
        if str(deployed_addresses_hash).lower() != str(manifest.get("deployedAddressesHash")).lower():
            raise DeploymentManifestError(
                f"deployed_addresses.json hash {deployed_addresses_hash} != manifest {manifest.get('deployedAddressesHash')}"
            )
    if deployed_addresses_contracts is not None:
        for name in needed:
            a = deployed_addresses_contracts.get(name)
            if a and not _addr_eq(a, _entry_addr(contracts[name])):
                raise DeploymentManifestError(
                    f"deployed_addresses.json {name} {a} != manifest {_entry_addr(contracts[name])}"
                )

    # local ABI hash.
    if local_abi_hash is not None:
        for name in needed:
            h = local_abi_hash(name)
            if h and str(h).lower() != str(contracts[name].get("abiHash")).lower():
                raise DeploymentManifestError(
                    f"local ABI hash for {name} {h} != manifest {contracts[name].get('abiHash')} (stale ABI?)"
                )

    # on-chain runtime code hashes.
    if fetch_code is not None:
        for name in needed:
            entry = contracts[name]
            got = fetch_code(_entry_addr(entry))
            if str(got).lower() != _entry_code_hash(entry).lower():
                raise DeploymentManifestError(
                    f"on-chain runtime code hash for {name} {got} != manifest {_entry_code_hash(entry)} (altered bytecode?)"
                )

    # on-chain wiring re-fetch.
    if fetch_wiring is not None:
        for consumer, getter, target in _REQUIRED_WIRING:
            if consumer not in needed:
                continue
            got = fetch_wiring(_entry_addr(contracts[consumer]), getter)
            want = _entry_addr(contracts[target])
            if not _addr_eq(got, want):
                raise DeploymentManifestError(
                    f"on-chain wiring {consumer}.{getter} {got} != {target} {want}"
                )


_REGISTRY_DEPRECATED = 2
_REGISTRY_RETIRED = 3


def verify_against_registry(
    addresses: dict,
    *,
    chain_id: int,
    registry_chain_id: int,
    lookup,
    entry,
    latest_version,
    code_hash,
) -> dict:
    """Check the DO's pinned contracts against FileTrustAddressRegistry (Phase 2).

    The registry is checked, never followed: each pinned contract must be registered
    under its own name, not be Retired, and still run the registered code, on the chain
    this DO is configured for. Raises DeploymentManifestError otherwise (fail closed).
    Returns the names with a newer registered version and those marked Deprecated, for
    the user to update through a verified release; the DO keeps its pinned addresses.

    lookup(address) -> (name, version or 0); entry(name, version) -> mapping with
    "status" and "codeHash"; latest_version(name) -> int; code_hash(address) -> hex.
    """
    if int(registry_chain_id) != int(chain_id):
        raise DeploymentManifestError(
            f"address registry describes chain {registry_chain_id}, not the configured chain {chain_id}"
        )
    newer: list[str] = []
    deprecated: list[str] = []
    for name, address in addresses.items():
        if not address:
            continue
        registered_name, version = lookup(address)
        if not version:
            raise DeploymentManifestError(f"{name} {address} is not registered in the address registry")
        if registered_name != name:
            raise DeploymentManifestError(f"{name} {address} is registered as {registered_name}")
        record = entry(name, version)
        status = int(record["status"])
        if status >= _REGISTRY_RETIRED:
            raise DeploymentManifestError(f"{name} version {version} is retired in the address registry")
        if str(code_hash(address)).lower() != str(record["codeHash"]).lower():
            raise DeploymentManifestError(f"{name} {address} no longer runs the registered code")
        if status == _REGISTRY_DEPRECATED:
            deprecated.append(name)
        if int(latest_version(name)) > int(version):
            newer.append(name)
    return {"newer": sorted(newer), "deprecated": sorted(deprecated)}


def enforce_manifest(path: str | None, *, chain_id: int, addresses: dict) -> None:
    """Load and verify the manifest at path. An empty path is a no-op (opt-in); a
    present-but-invalid manifest, or any mismatch, raises."""
    if not path:
        return
    verify_manifest(load_manifest(path), chain_id=chain_id, addresses=addresses)
