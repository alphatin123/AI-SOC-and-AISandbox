"""Read-only investigation tools with an independent tool-side log.

The agent only ever receives ``Untrusted`` results. Every call is recorded in
``ToolSideLog`` which is *not* the ledger: it is the second, independent
record used for reconciliation (paper §VIII-D). Rate limits are per case so a
flood of alerts cannot exhaust shared resources.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..crypto import Clock
from ..idps import FlowRecord
from .untrusted import Untrusted, wrap


class ToolError(Exception):
    pass


@dataclass
class ToolCallRecord:
    case_id: str
    tool: str
    args: Dict[str, Any]
    ok: bool
    at: str
    flags: List[str] = field(default_factory=list)


class ToolSideLog:
    def __init__(self) -> None:
        self.calls: List[ToolCallRecord] = []
        self.receipts: List[Any] = []  # Signed ActionReceipt objects from the executor

    def record_call(self, rec: ToolCallRecord) -> None:
        self.calls.append(rec)

    def record_receipt(self, signed_receipt: Any) -> None:
        self.receipts.append(signed_receipt)


class TelemetryStore:
    """Synthetic backing store for the read-only tools."""

    def __init__(self) -> None:
        self.flows: Dict[str, FlowRecord] = {}
        self.host_windows: Dict[str, Dict[str, Any]] = {}
        self.logins: Dict[str, List[Dict[str, Any]]] = {}
        self.ioc: Dict[str, Dict[str, Any]] = {}

    def add_flow(self, f: FlowRecord) -> None:
        self.flows[f.flow_id] = f


class ReadOnlyTools:
    def __init__(self, store: TelemetryStore, log: ToolSideLog, clock: Clock, max_calls_per_case: int = 20) -> None:
        self.store = store
        self.log = log
        self.clock = clock
        self.max_calls_per_case = max_calls_per_case
        self._calls: Dict[str, int] = {}
        self._registry: Dict[str, Callable[..., Any]] = {
            "get_flow": self._get_flow,
            "get_host_window": self._get_host_window,
            "get_recent_logins": self._get_recent_logins,
            "lookup_ioc": self._lookup_ioc,
        }

    @property
    def names(self) -> List[str]:
        return sorted(self._registry)

    def call(self, case_id: str, tenant: str, tool: str, **args: Any) -> Untrusted[Any]:
        n = self._calls.get(case_id, 0)
        if n >= self.max_calls_per_case:
            self.log.record_call(ToolCallRecord(case_id, tool, args, False, self.clock.iso(), ["rate_limited"]))
            raise ToolError("per-case tool budget exhausted")
        self._calls[case_id] = n + 1
        fn = self._registry.get(tool)
        if fn is None:
            self.log.record_call(ToolCallRecord(case_id, tool, args, False, self.clock.iso(), ["unknown_tool"]))
            raise ToolError(f"unknown tool {tool}")
        try:
            result = fn(tenant=tenant, **args)
        except ToolError:
            self.log.record_call(ToolCallRecord(case_id, tool, args, False, self.clock.iso()))
            raise
        wrapped = wrap(f"tool:{tool}", result)
        self.log.record_call(ToolCallRecord(case_id, tool, args, True, self.clock.iso(), wrapped.flags))
        return wrapped

    # --- tool implementations: tenant-scoped, read-only -------------------------------
    def _get_flow(self, tenant: str, flow_id: str) -> Dict[str, Any]:
        f = self.store.flows.get(flow_id)
        if f is None or f.tenant != tenant:
            raise ToolError("flow not found in tenant scope")
        return {
            "flow_id": f.flow_id, "src_host": f.src_host, "dst_ip": f.dst_ip, "dst_port": f.dst_port,
            "bytes_in": f.bytes_in, "bytes_out": f.bytes_out, "duration_s": f.duration_s,
            "conn_failures": f.conn_failures, "login_failures": f.login_failures,
            "distinct_dst_ports": f.distinct_dst_ports, "log_excerpt": f.log_excerpt,
        }

    def _get_host_window(self, tenant: str, host: str) -> Dict[str, Any]:
        w = self.store.host_windows.get(f"{tenant}/{host}")
        if w is None:
            raise ToolError("no host window")
        return dict(w)

    def _get_recent_logins(self, tenant: str, host: str) -> Dict[str, Any]:
        return {"host": host, "logins": list(self.store.logins.get(f"{tenant}/{host}", []))}

    def _lookup_ioc(self, tenant: str, indicator: str) -> Dict[str, Any]:
        return dict(self.store.ioc.get(indicator, {"indicator": indicator, "match": False}))
