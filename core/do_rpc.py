"""Resilient JSON-RPC provider for Data Owner blockchain reads.

Only idempotent JSON-RPC methods are retried. Transaction submission is never
retried here because an interrupted response does not prove that the node
rejected the transaction.
"""

from __future__ import annotations

import random
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from web3 import Web3
from web3.providers.rpc import HTTPProvider


_SAFE_METHOD_PREFIXES = (
    "eth_get",
    "eth_call",
    "eth_estimateGas",
    "eth_blockNumber",
    "eth_chainId",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_feeHistory",
    "net_",
    "web3_",
)


def is_safe_rpc_method(method: str) -> bool:
    return str(method).startswith(_SAFE_METHOD_PREFIXES)


# Errors that mean "committed, but not readable yet" rather than "wrong".
# Deliberately narrow: a revert or a bad argument is a real answer and must
# surface at once. These are what a Cosmos EVM node returns while its EVM index
# catches up with a block it has just committed; a single-process dev chain
# never produces them, so this changes nothing there.
_NOT_YET_VISIBLE = (
    "tx not found",
    "not found: hash",
    "failed to get receipts from comet block",
    "failed to get rpc block",
    "failed to fetch header by number",
    "is not ready",
    "height is not available",
    "requested block height is bigger",
)


def _chain_not_yet_visible(response: Any) -> bool:
    if not isinstance(response, dict):
        return False
    error = response.get("error")
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", "")).lower()
    if "reverted" in message or "invalid" in message:
        return False
    return any(marker in message for marker in _NOT_YET_VISIBLE)


class ResilientHTTPProvider(HTTPProvider):
    """HTTP provider with bounded retries for read-only JSON-RPC methods."""

    def __init__(
        self,
        endpoint_uri: str,
        *,
        timeout_seconds: float = 30.0,
        attempts: int = 4,
        backoff_initial_seconds: float = 0.25,
        backoff_max_seconds: float = 2.0,
    ) -> None:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=16,
            pool_maxsize=32,
            max_retries=0,
            pool_block=True,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        super().__init__(
            endpoint_uri=endpoint_uri,
            request_kwargs={"timeout": max(1.0, float(timeout_seconds))},
            session=session,
        )
        self._attempts = max(1, int(attempts))
        self._backoff_initial = max(0.0, float(backoff_initial_seconds))
        self._backoff_max = max(self._backoff_initial, float(backoff_max_seconds))

    @staticmethod
    def _usable_response(response: Any) -> bool:
        if not isinstance(response, dict):
            return False
        if _chain_not_yet_visible(response):
            # Not an answer yet -- let the caller retry rather than treat a
            # "still indexing" reply as a final result.
            return False
        if response.get("error") is not None:
            return True
        return "result" in response and response.get("result") is not None

    def make_request(self, method: str, params: Any) -> Any:
        if not is_safe_rpc_method(method):
            return super().make_request(method, params)

        last_error: Exception | None = None
        for attempt in range(self._attempts):
            try:
                response = super().make_request(method, params)
                if self._usable_response(response):
                    return response
                last_error = ConnectionError(
                    f"JSON-RPC {method} returned no usable result"
                )
            except (
                requests.RequestException,
                ConnectionError,
                ConnectionResetError,
                TimeoutError,
                OSError,
            ) as exc:
                last_error = exc

            if attempt + 1 < self._attempts:
                delay = min(
                    self._backoff_max,
                    self._backoff_initial * (2**attempt),
                )
                if delay:
                    time.sleep(delay + random.uniform(0.0, min(0.1, delay / 4)))

        if last_error is not None:
            raise last_error
        raise ConnectionError(f"JSON-RPC {method} failed without a response")


def new_web3(config: Any) -> Web3:
    provider = ResilientHTTPProvider(
        str(config.RPC_URL),
        timeout_seconds=float(getattr(config, "RPC_TIMEOUT_SECONDS", 30)),
        attempts=int(getattr(config, "RPC_READ_ATTEMPTS", 4)),
        backoff_initial_seconds=float(
            getattr(config, "RPC_RETRY_INITIAL_SECONDS", 0.25)
        ),
        backoff_max_seconds=float(getattr(config, "RPC_RETRY_MAX_SECONDS", 2.0)),
    )
    return Web3(provider)
