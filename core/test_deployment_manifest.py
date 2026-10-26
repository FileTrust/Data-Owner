"""A.0 DO-side deployment-manifest verification tests (no web3/GUI required)."""
import importlib.util
import json
import pathlib
import pytest

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("do_deployment_manifest", _HERE / "do_deployment_manifest.py")
DM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(DM)

SNAP = "0x00000000000000000000000000000000000000AA"
STOR = "0x00000000000000000000000000000000000000BB"
CAP = "0x00000000000000000000000000000000000000CC"
FILE = "0x00000000000000000000000000000000000000DD"
REG = "0x00000000000000000000000000000000000000EE"
CERT = "0x00000000000000000000000000000000000000FF"
BATCH = "0x0000000000000000000000000000000000000B1C"
DR = "0x0000000000000000000000000000000000000D1E"


def _c(addr, code, abi):
    return {
        "contractAddress": addr, "address": addr,
        "runtimeCodeHash": "codehash-" + code, "codeHash": "codehash-" + code,
        "abiHash": "abihash-" + abi, "contractVersion": "a0.1",
        "deploymentBlock": "10", "deploymentTransactionHash": "0xtx" + addr[2:6],
    }


def _manifest():
    return {
        "manifestKind": "filetrust-deployment-manifest", "version": 1,
        "schema": "filetrust-deployment-manifest/1", "chainId": "31337",
        "deployedAddressesHash": "0xda5eed",
        "contracts": {
            "PartitionSnapshotProofSC": _c(SNAP, "snap", "snap"),
            "StorageProofSC": _c(STOR, "stor", "stor"),
            "CapacityProofSC": _c(CAP, "cap", "cap"),
            "FileRegistrationSC": _c(FILE, "file", "file"),
            "VaultKeeperRegistry": _c(REG, "reg", "reg"),
            "CapacityCertificationSC": _c(CERT, "cert", "cert"),
            "CapacityIncrementalBatchSC": _c(BATCH, "batch", "batch"),
            "DeletionReleaseSC": _c(DR, "dr", "dr"),
        },
        "wiring": {
            "StorageProofSC.partitionSnapshotProof": SNAP,
            "StorageProofSC.capacityProof": CAP,
            "CapacityProofSC.partitionSnapshotProof": SNAP,
            "CapacityProofSC.storageProof": STOR,
            "PartitionSnapshotProofSC.storageProof": STOR,
            "PartitionSnapshotProofSC.capacityProof": CAP,
            "CapacityProofSC.certificationContract": CERT,
            "CapacityCertificationSC.capacityProofSC": CAP,
            "PartitionSnapshotProofSC.incrementalBatch": BATCH,
            "CapacityIncrementalBatchSC.snapshotProof": SNAP,
            "CapacityIncrementalBatchSC.capacityProof": CAP,
            "FileRegistrationSC.deletionRelease": DR,
            "PartitionSnapshotProofSC.deletionRelease": DR,
            "StorageProofSC.deletionRelease": DR,
            "DeletionReleaseSC.fileRegistration": FILE,
            "DeletionReleaseSC.snapshotProof": SNAP,
            "DeletionReleaseSC.storageProof": STOR,
        },
    }


def _addrs():
    return {
        "StorageProofSC": STOR, "CapacityProofSC": CAP,
        "FileRegistrationSC": FILE, "DeletionReleaseSC": DR,
    }


def _code_map():
    return {SNAP: "codehash-snap", STOR: "codehash-stor", CAP: "codehash-cap",
            FILE: "codehash-file", REG: "codehash-reg", CERT: "codehash-cert",
            BATCH: "codehash-batch", DR: "codehash-dr"}


def _consistent_kwargs(m):
    codes = _code_map()
    def fetch_code(a):
        for k, v in codes.items():
            if k.lower() == a.lower():
                return v
        return "0x"
    def fetch_wiring(consumer, getter):
        for c, g, t in DM._REQUIRED_WIRING:
            if DM._entry_addr(m["contracts"][c]) == consumer and g == getter:
                return DM._entry_addr(m["contracts"][t])
        return "0x0"
    def local_abi(name):
        return m["contracts"][name]["abiHash"]
    return dict(fetch_code=fetch_code, fetch_wiring=fetch_wiring, local_abi_hash=local_abi)


def test_consistent_stack_passes():
    m = _manifest()
    DM.verify_manifest(m, chain_id=31337, addresses=_addrs(), **_consistent_kwargs(m))


def test_altered_runtime_bytecode_rejected():
    m = _manifest()
    kw = _consistent_kwargs(m)
    kw["fetch_code"] = lambda a: "TAMPERED"
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs(), **kw)


def test_stale_abi_rejected():
    m = _manifest()
    kw = _consistent_kwargs(m)
    kw["local_abi_hash"] = lambda name: "STALE"
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs(), **kw)


def test_incorrect_wiring_rejected():
    m = _manifest()
    kw = _consistent_kwargs(m)
    kw["fetch_wiring"] = lambda c, g: "0x00000000000000000000000000000000000000FF"
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs(), **kw)


def test_manifest_internal_wiring_mismatch_rejected():
    m = _manifest()
    m["wiring"]["StorageProofSC.partitionSnapshotProof"] = "0x00000000000000000000000000000000000000FF"
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs())


@pytest.mark.parametrize("field", ["deploymentBlock", "deploymentTransactionHash", "contractVersion", "runtimeCodeHash", "abiHash"])
def test_missing_required_contract_field_rejected(field):
    m = _manifest()
    m["contracts"]["StorageProofSC"][field] = ""
    if field in ("runtimeCodeHash",):
        m["contracts"]["StorageProofSC"]["codeHash"] = ""
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs())


def test_missing_schema_rejected():
    m = _manifest(); m["schema"] = ""
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs())


def test_wrong_deployed_addresses_hash_rejected():
    m = _manifest()
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs(),
                           deployed_addresses_hash="0xDIFFERENT")


def test_wrong_deployed_addresses_contract_rejected():
    m = _manifest()
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=_addrs(),
                           deployed_addresses_hash="0xda5eed",
                           deployed_addresses_contracts={"StorageProofSC": "0x0000000000000000000000000000000000009999"})


def test_chain_id_mismatch_rejected():
    m = _manifest()
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=1, addresses=_addrs())


def test_configured_address_mismatch_rejected():
    m = _manifest()
    addrs = _addrs(); addrs["StorageProofSC"] = "0x0000000000000000000000000000000000001234"
    with pytest.raises(DM.DeploymentManifestError):
        DM.verify_manifest(m, chain_id=31337, addresses=addrs)


def test_wrong_kind_rejected(tmp_path):
    p = tmp_path / "m.json"; p.write_text(json.dumps({"manifestKind": "other"}))
    with pytest.raises(DM.DeploymentManifestError):
        DM.load_manifest(str(p))


def test_empty_path_noop():
    DM.enforce_manifest("", chain_id=31337, addresses=_addrs())
