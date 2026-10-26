"""Transaction-only JSONL logging for the Data Owner app."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

_CALL_LOGGER_INSTALLED = False
_ORIGINAL_CONTRACT_FUNCTION_CALL = None


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "hex"):
        return value.hex()
    return str(value)


def _iso_ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=_json_default, separators=(",", ":")) + "\n")


def transaction_log_path(C) -> Path:
    raw = Path(str(getattr(C.config, "TRANSACTION_LOG_PATH", "") or "")).expanduser()
    if raw.is_absolute():
        return raw
    return (Path(C.BASE_DIR) / raw).resolve()


def _chain_id(C) -> str:
    try:
        return str(C.w3.eth.chain_id)
    except Exception:
        return ""


def _base(
    C,
    *,
    tag: str,
    transaction_kind: str,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    status: str,
) -> dict[str, Any]:
    return {
        "tag": tag,
        "facility": "data_owner",
        "source": "DO",
        "transaction_kind": transaction_kind,
        "network": "",
        "chain_id": _chain_id(C),
        "timestamp": _iso_ts(),
        "rpc_url": str(getattr(C.config, "RPC_URL", "") or ""),
        "actor_address": actor_address or "",
        "contract_name": contract_name or "",
        "function_name": function_name or "",
        "contract_address": contract_address or "",
        "to_address": contract_address or "",
        "value_wei": "0",
        "transaction_hash": "",
        "block_number": "",
        "status": status,
        "gas_used": "0",
        "gas_price_wei": "0",
        "effective_gas_price_wei": "0",
        "total_cost_wei": "0",
        "total_cost_eth": "0",
    }


def _safe_details(details: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key, value in details.items():
        if value is None:
            continue
        safe["data_timestamp" if key == "timestamp" else key] = value
    return safe


def function_name(fn: Any, fallback: str = "") -> str:
    return str(
        getattr(fn, "fn_name", "")
        or getattr(fn, "function_identifier", "")
        or fallback
        or ""
    )


def contract_address(fn: Any, fallback: str = "") -> str:
    return str(getattr(fn, "address", "") or fallback or "")


def contract_name_for_address(C, address: str, fallback: str = "contract") -> str:
    target = str(address or "").lower()
    if not target:
        return fallback
    known = {
        "AccessControlFT": getattr(C.config, "ACL_ADDRESS", ""),
        "DataVault": getattr(C.config, "DV_ADDRESS", ""),
        "GuardianRegistry": getattr(C.config, "GUARDIAN_REGISTRY_ADDRESS", ""),
        "VaultKeeperRegistry": getattr(C.config, "VAULT_KEEPER_REGISTRY_ADDRESS", ""),
        "ZkDkgCoordinatorV2": getattr(C.config, "ZKDKG_COORDINATOR_V2_ADDRESS", ""),
        "GuardianShareProof": getattr(C.config, "GUARDIAN_SHARE_PROOF_ADDRESS", ""),
        "RewardManager": getattr(C.config, "REWARD_MANAGER_ADDRESS", ""),
        "TElGv2": getattr(C.config, "TELG_V2_ADDRESS", ""),
        "FileRegistrationSC": getattr(C.config, "FILE_REGISTRATION_ADDRESS", ""),
        "VKEscrow": getattr(C.config, "VK_ESCROW_ADDRESS", ""),
        "StorageReceiptDispute": getattr(C.config, "STORAGE_RECEIPT_DISPUTE_ADDRESS", ""),
    }
    for name, known_address in known.items():
        if str(known_address or "").lower() == target:
            return name
    return fallback


def log_eth_call(
    C,
    *,
    contract_name: str,
    function_name: str,
    contract_address: str = "",
    actor_address: str = "",
    status: str,
    error: str = "",
    **details: Any,
) -> None:
    payload = _base(
        C,
        tag=f"do:{contract_name}.{function_name}",
        transaction_kind="eth_call",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=status,
    )
    payload.update(_safe_details(details))
    if error:
        payload["error"] = str(error)
    append_jsonl(transaction_log_path(C), payload)


def call(
    C,
    fn: Any,
    *,
    contract_name: str = "",
    function_name: str = "",
    contract_address: str = "",
    actor_address: str = "",
    **details: Any,
) -> Any:
    resolved_function = function_name or function_name_from_contract_function(fn)
    resolved_address = contract_address or contract_address_from_contract_function(fn)
    resolved_contract = contract_name or contract_name_for_address(C, resolved_address)
    try:
        result = fn.call()
        extra = dict(details)
        if isinstance(result, (list, tuple)):
            extra.setdefault("result_count", len(result))
        log_eth_call(
            C,
            contract_name=resolved_contract,
            function_name=resolved_function,
            contract_address=resolved_address,
            actor_address=actor_address,
            status="success",
            **extra,
        )
        return result
    except Exception as exc:
        log_eth_call(
            C,
            contract_name=resolved_contract,
            function_name=resolved_function,
            contract_address=resolved_address,
            actor_address=actor_address,
            status="failed",
            error=str(exc),
            **details,
        )
        raise


def install_contract_call_logger(C) -> None:
    """Log every DO Web3 contract .call() without touching non-DO apps."""
    global _CALL_LOGGER_INSTALLED, _ORIGINAL_CONTRACT_FUNCTION_CALL
    if _CALL_LOGGER_INSTALLED:
        return
    try:
        from web3.contract.contract import ContractFunction
    except Exception:
        return

    original_call = ContractFunction.call
    _ORIGINAL_CONTRACT_FUNCTION_CALL = original_call

    def logged_call(self, *args, **kwargs):
        resolved_function = function_name_from_contract_function(self)
        resolved_address = contract_address_from_contract_function(self)
        resolved_contract = contract_name_for_address(C, resolved_address)
        actor_address = ""
        tx_params = kwargs.get("transaction")
        if isinstance(tx_params, dict):
            actor_address = str(tx_params.get("from", "") or "")
        try:
            result = original_call(self, *args, **kwargs)
            details: dict[str, Any] = {}
            if isinstance(result, (list, tuple)):
                details["result_count"] = len(result)
            log_eth_call(
                C,
                contract_name=resolved_contract,
                function_name=resolved_function,
                contract_address=resolved_address,
                actor_address=actor_address,
                status="success",
                **details,
            )
            return result
        except Exception as exc:
            log_eth_call(
                C,
                contract_name=resolved_contract,
                function_name=resolved_function,
                contract_address=resolved_address,
                actor_address=actor_address,
                status="failed",
                error=str(exc),
            )
            raise

    ContractFunction.call = logged_call
    _CALL_LOGGER_INSTALLED = True


def function_name_from_contract_function(fn: Any) -> str:
    return function_name(fn, "")


def contract_address_from_contract_function(fn: Any) -> str:
    return contract_address(fn, "")


def log_contract_transaction(
    C,
    w3,
    *,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    tx: dict[str, Any],
    tx_hash: Any,
    receipt: Any,
    **details: Any,
) -> None:
    gas_used = int(receipt.get("gasUsed", 0) or 0)
    gas_price = int(tx.get("gasPrice", 0) or 0)
    effective_gas_price = int(receipt.get("effectiveGasPrice", gas_price) or gas_price)
    total_cost_wei = gas_used * effective_gas_price
    payload = _base(
        C,
        tag=f"do:{contract_name}.{function_name}",
        transaction_kind="contract_transaction",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=str(receipt.get("status", "")),
    )
    payload.update(
        {
            "to_address": str(tx.get("to", "") or contract_address or ""),
            "value_wei": str(int(tx.get("value", 0) or 0)),
            "transaction_hash": tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash),
            "block_number": str(receipt.get("blockNumber", "")),
            "gas_used": str(gas_used),
            "gas_price_wei": str(gas_price),
            "effective_gas_price_wei": str(effective_gas_price),
            "total_cost_wei": str(total_cost_wei),
            "total_cost_eth": str(w3.from_wei(total_cost_wei, "ether")),
        }
    )
    payload.update(_safe_details(details))
    append_jsonl(transaction_log_path(C), payload)


def log_contract_transaction_attempt(
    C,
    *,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    status: str,
    error: str = "",
    **details: Any,
) -> None:
    payload = _base(
        C,
        tag=f"do:{contract_name}.{function_name}",
        transaction_kind="contract_transaction_attempt",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=status,
    )
    payload.update(_safe_details(details))
    if error:
        payload["error"] = str(error)
    append_jsonl(transaction_log_path(C), payload)
