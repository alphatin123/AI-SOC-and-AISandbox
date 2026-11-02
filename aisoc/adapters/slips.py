"""Slips (Stratosphere Linux IPS) as the AI-IDPS front end.

Slips (https://github.com/stratosphereips/StratosphereLinuxIPS) is a
behaviour-based IDS/IPS with heuristic, threat-intelligence and machine
learning detection modules. It writes every piece of *evidence* and every
*alert* to ``<output>/alerts.json`` as one IDMEFv2 message per line (Slips
>= 1.1, ``Version: 2.D.V03``).

This adapter reads that file (and optionally the Zeek ``conn.log`` Slips keeps
next to it) and maps Slips output onto the paper's dual_model branches:

* **known branch** — evidence types that name a concrete attack behaviour
  (port scans, password guessing, C&C, data upload, TI hits, ...) become an
  :class:`~aisoc.idps.ExternalKnown` verdict with a family label and, where
  the mapping is unambiguous, an ATT&CK technique id;
* **normality branch** — Slips' ML/anomaly modules (``ANOMALOUS_FLOW``,
  ``ML_*_MALICIOUS_FLOW``, ``MALICIOUS_FLOW``) are "something is wrong but it
  is not a named class" signals and become an
  :class:`~aisoc.idps.ExternalAnomaly`;
* everything else (young domains, unknown ports, long connections, ...) is a
  weak indicator: the known branch *rejects* it, so without an anomaly signal
  the case is ``UNKNOWN`` and goes to a human. Missing data is never normal.

Evidence lines are grouped per Slips profile and time window (``Source IP`` +
``Note.timewindow``), the same unit Slips uses to raise an alert. The free
text ``Description`` is kept only as *untrusted* ``log_excerpt``.

Slips is GPL-2.0; this module consumes its output files and contains no
Slips code. Scores produced here are Slips' own confidence values, which are
**not** calibrated probabilities in the sense of paper §V; ``tau_k`` for this
branch therefore defaults to 0.5 and must be tuned per deployment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

from ..canonical import digest
from ..idps import ExternalAnomaly, ExternalKnown, FlowRecord
from ..soc import AISOC, CaseResult

SLIPS_SOURCE = "slips"
IDMEF_EVENT = "Event"        # one Slips evidence
IDMEF_INCIDENT = "Incident"  # one Slips alert (accumulated evidence over a time window)

THREAT_LEVEL_WEIGHT: Dict[str, float] = {"info": 0.0, "low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}

# Slips EvidenceType -> (family label for the known branch, ATT&CK technique or None).
# Only behaviours that name a concrete attack class are listed; the rest are weak indicators.
KNOWN_FAMILY_MAP: Dict[str, Tuple[str, Optional[str]]] = {
    "HORIZONTAL_PORT_SCAN": ("port_scan", "T1046"),
    "VERTICAL_PORT_SCAN": ("port_scan", "T1046"),
    "DHCP_SCAN": ("port_scan", "T1046"),
    "GRE_SCAN": ("port_scan", "T1046"),
    "ARP_SCAN": ("recon", "T1018"),
    "DNS_ARPA_SCAN": ("recon", "T1018"),
    "ICMP_TIMESTAMP_SCAN": ("recon", "T1018"),
    "ICMP_ADDRESS_SCAN": ("recon", "T1018"),
    "ICMP_ADDRESS_MASK_SCAN": ("recon", "T1018"),
    "PASSWORD_GUESSING": ("bruteforce", "T1110"),
    "SMTP_LOGIN_BRUTEFORCE": ("bruteforce", "T1110"),
    "DATA_UPLOAD": ("exfiltration", "T1041"),
    "COMMAND_AND_CONTROL_CHANNEL": ("c2", "T1071"),
    "DGA_NXDOMAINS": ("c2", "T1568.002"),
    "HIGH_ENTROPY_DNS_ANSWER": ("c2", "T1071.004"),
    "MALICIOUS_JA3": ("c2", "T1573"),
    "MALICIOUS_JA3S": ("c2", "T1573"),
    "MALICIOUS_JARM": ("c2", "T1573"),
    "MALICIOUS_SSL_CERT": ("c2", "T1573"),
    "TOR_EXIT_NODE": ("c2", "T1090.003"),
    "MALICIOUS_DOWNLOADED_FILE": ("malware_download", "T1105"),
    "EXECUTABLE_MIME_TYPE": ("malware_download", "T1105"),
    "PASTEBIN_DOWNLOAD": ("malware_download", "T1102"),
    "MITM_ARP_ATTACK": ("mitm", "T1557.002"),
    "GRE_TUNNEL": ("tunnel", "T1572"),
    "THREAT_INTELLIGENCE_BLACKLISTED_ASN": ("threat_intel", None),
    "THREAT_INTELLIGENCE_FROM_BLACKLISTED_IP": ("threat_intel", None),
    "THREAT_INTELLIGENCE_TO_BLACKLISTED_IP": ("threat_intel", None),
    "THREAT_INTELLIGENCE_BLACKLISTED_DNS_ANSWER": ("threat_intel", None),
    "THREAT_INTELLIGENCE_BLACKLISTED_DOMAIN": ("threat_intel", None),
    "THREAT_INTELLIGENCE_ANSWER_OF_BLACKLISTED_QUERY": ("threat_intel", None),
    "THREAT_INTELLIGENCE_MALICIOUS_URL": ("threat_intel", None),
    "MALICIOUS_IP_FROM_P2P_NETWORK": ("threat_intel", None),
}

# Evidence produced by Slips' learned/anomaly detectors: no named class, "unlike normal".
ANOMALY_TYPES: Set[str] = {"ANOMALOUS_FLOW", "MALICIOUS_FLOW", "ML_LINEAR_MALICIOUS_FLOW", "ML_ONLINE_MALICIOUS_FLOW"}

UNCLASSIFIED = "unclassified"
_FAILED_CONN_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


def _enum_name(value: Any) -> str:
    """'EvidenceType.PASSWORD_GUESSING' | 'password_guessing' | 'ThreatLevel.HIGH' -> upper name."""
    s = str(value).strip()
    if "." in s:
        s = s.rsplit(".", 1)[1]
    return s.upper()


def threat_level_weight(value: Any) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, min(1.0, float(value)))
    return THREAT_LEVEL_WEIGHT.get(_enum_name(value).lower(), 0.0)


@dataclass
class SlipsEvidence:
    """One Slips evidence line (IDMEFv2 ``Status: Event``)."""

    id: str
    evidence_type: str
    source_module: str
    threat_level: float
    confidence: float
    description: str
    source_ip: str
    source_kind: str  # IP | Hostname | URL
    target_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    proto: Optional[str]
    timewindow: Optional[int]
    uids: List[str]
    start_time: str
    slips_version: str
    priority: str
    ti_sources: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def family(self) -> Optional[str]:
        m = KNOWN_FAMILY_MAP.get(self.evidence_type)
        return m[0] if m else None

    @property
    def technique(self) -> Optional[str]:
        m = KNOWN_FAMILY_MAP.get(self.evidence_type)
        return m[1] if m else None

    @property
    def is_anomaly_signal(self) -> bool:
        return self.evidence_type in ANOMALY_TYPES


@dataclass
class SlipsIncident:
    """One Slips alert (IDMEFv2 ``Status: Incident``)."""

    id: str
    source_ip: str
    correl_ids: List[str]
    accumulated_threat_level: Optional[float]
    timewindow: Optional[int]
    start_time: str
    end_time: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SlipsParseResult:
    evidence: List[SlipsEvidence] = field(default_factory=list)
    incidents: List[SlipsIncident] = field(default_factory=list)
    malformed: int = 0
    slips_versions: Set[str] = field(default_factory=set)


def _first_endpoint(entries: Any) -> Tuple[str, str, Optional[int], Optional[str], List[str]]:
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        return "", "", None, None, []
    e = entries[0]
    kind, value = "", ""
    for k in ("IP", "Hostname", "URL"):
        if e.get(k):
            kind, value = k, str(e[k])
            break
    port = None
    if isinstance(e.get("Port"), list) and e["Port"]:
        try:
            port = int(e["Port"][0])
        except (TypeError, ValueError):
            port = None
    proto = None
    if isinstance(e.get("Protocol"), list) and e["Protocol"]:
        proto = str(e["Protocol"][0]).lower()
    ti = [str(x) for x in e.get("TI", [])] if isinstance(e.get("TI"), list) else []
    return kind, value, port, proto, ti


def parse_idmef_record(rec: Dict[str, Any]) -> Union[SlipsEvidence, SlipsIncident, None]:
    """Parse one IDMEFv2 dict as written by Slips. Returns None if it is not recognisable."""
    if not isinstance(rec, dict) or str(rec.get("Version", "")).split(".")[0] != "2":
        return None
    note: Dict[str, Any] = {}
    raw_note = rec.get("Note")
    if isinstance(raw_note, str) and raw_note:
        try:
            note = json.loads(raw_note)
        except ValueError:
            note = {}
    elif isinstance(raw_note, dict):
        note = raw_note
    analyzer = rec.get("Analyzer") or {}
    version = str(analyzer.get("Model", "")) if isinstance(analyzer, dict) else ""
    status = rec.get("Status")
    src_kind, src_value, src_port, proto, src_ti = _first_endpoint(rec.get("Source"))
    tw = note.get("timewindow")
    try:
        tw_int: Optional[int] = int(tw) if tw is not None else None
    except (TypeError, ValueError):
        tw_int = None

    if status == IDMEF_INCIDENT:
        atl = note.get("accumulated_threat_level")
        return SlipsIncident(
            id=str(rec.get("ID", "")),
            source_ip=src_value,
            correl_ids=[str(c) for c in rec.get("CorrelID", []) or []],
            accumulated_threat_level=float(atl) if isinstance(atl, (int, float)) else None,
            timewindow=tw_int,
            start_time=str(rec.get("StartTime", "")),
            end_time=note.get("EndTime"),
            raw=rec,
        )
    if status != IDMEF_EVENT:
        return None
    _, tgt_value, dst_port, _, tgt_ti = _first_endpoint(rec.get("Target"))
    etype = _enum_name(note.get("evidence_type", "")) if note.get("evidence_type") else ""
    try:
        confidence = float(rec.get("Confidence", 0.0))
    except (TypeError, ValueError):
        confidence = 0.0
    uids = note.get("uids") or []
    return SlipsEvidence(
        id=str(rec.get("ID", "")),
        evidence_type=etype,
        source_module=str(note.get("source_module", "")),
        threat_level=threat_level_weight(note.get("threat_level", rec.get("Priority", "info"))),
        confidence=max(0.0, min(1.0, confidence)),
        description=str(rec.get("Description", "")),
        source_ip=src_value,
        source_kind=src_kind,
        target_ip=tgt_value or None,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        timewindow=tw_int,
        uids=[str(u) for u in uids] if isinstance(uids, list) else [],
        start_time=str(rec.get("StartTime", "")),
        slips_version=version,
        priority=str(rec.get("Priority", "")),
        ti_sources=src_ti + tgt_ti,
        raw=rec,
    )


def parse_alerts_json(lines: Iterable[str]) -> SlipsParseResult:
    out = SlipsParseResult()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            out.malformed += 1
            continue
        parsed = parse_idmef_record(rec)
        if isinstance(parsed, SlipsEvidence):
            out.evidence.append(parsed)
            if parsed.slips_version:
                out.slips_versions.add(parsed.slips_version)
        elif isinstance(parsed, SlipsIncident):
            out.incidents.append(parsed)
        else:
            out.malformed += 1
    return out


def read_alerts_json(path: Union[str, Path]) -> SlipsParseResult:
    return parse_alerts_json(Path(path).read_text(encoding="utf-8", errors="replace").splitlines())


# ----------------------------------------------------------------------------- Zeek conn.log
@dataclass
class ZeekConnIndex:
    """uid -> conn.log row (JSON-lines or Zeek TSV). Gives the FlowRecord its volumetrics."""

    rows: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "ZeekConnIndex":
        idx = cls()
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        fields: Optional[List[str]] = None
        sep = "\t"
        for line in text.splitlines():
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith("#fields"):
                    fields = line.split(sep)[1:]
                elif line.startswith("#separator"):
                    tok = line.split(" ", 1)[1].strip()
                    sep = bytes(tok, "utf-8").decode("unicode_escape") if tok.startswith("\\x") else tok
                continue
            if line.startswith("{"):
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
            elif fields is not None:
                vals = line.split(sep)
                row = {k: (None if v in ("-", "(empty)") else v) for k, v in zip(fields, vals)}
            else:
                continue
            uid = row.get("uid")
            if uid:
                idx.rows[str(uid)] = row
        return idx

    @staticmethod
    def _num(row: Dict[str, Any], key: str) -> float:
        v = row.get(key)
        try:
            return float(v) if v is not None else 0.0
        except (TypeError, ValueError):
            return 0.0

    def aggregate(self, uids: Sequence[str]) -> Optional[Dict[str, float]]:
        rows = [self.rows[u] for u in uids if u in self.rows]
        if not rows:
            return None
        ts = sorted(self._num(r, "ts") for r in rows)
        pkts = sum(self._num(r, "orig_pkts") + self._num(r, "resp_pkts") for r in rows)
        duration = sum(self._num(r, "duration") for r in rows)
        if len(ts) >= 2:
            mean_iat_ms = 1000.0 * (ts[-1] - ts[0]) / (len(ts) - 1)
        else:
            mean_iat_ms = 1000.0 * duration / max(pkts - 1.0, 1.0)
        return {
            "bytes_out": sum(self._num(r, "orig_bytes") for r in rows),
            "bytes_in": sum(self._num(r, "resp_bytes") for r in rows),
            "pkts_out": sum(self._num(r, "orig_pkts") for r in rows),
            "pkts_in": sum(self._num(r, "resp_pkts") for r in rows),
            "duration_s": duration,
            "mean_iat_ms": mean_iat_ms,
            "conn_failures": float(sum(1 for r in rows if str(r.get("conn_state", "")) in _FAILED_CONN_STATES)),
            "short_window_conns": float(len(rows)),
            "distinct_dst_ports": float(len({r.get("id.resp_p") for r in rows if r.get("id.resp_p") is not None})),
        }


# ----------------------------------------------------------------------------- cases
@dataclass
class SlipsCase:
    """Everything the SOC needs for one (profile, time window) group of Slips evidence."""

    flow: FlowRecord
    known: ExternalKnown
    anomaly: Optional[ExternalAnomaly]
    evidence: List[SlipsEvidence]
    incidents: List[SlipsIncident]
    source_record: Dict[str, Any]


def _service_group(port: Optional[int]) -> str:
    return {22: "ssh", 53: "dns", 80: "web", 443: "web", 25: "mail", 587: "mail"}.get(port or -1, "default")


class SlipsAdapter:
    def __init__(self, tenant: str, conn_index: Optional[ZeekConnIndex] = None, tau_k: float = 0.5, min_threat_weight: float = 0.5) -> None:
        self.tenant = tenant
        self.conn_index = conn_index
        self.tau_k = tau_k
        self.min_threat_weight = min_threat_weight

    def known_verdict(self, group: Sequence[SlipsEvidence]) -> ExternalKnown:
        mapped = [e for e in group if e.family is not None]
        ids = [e.id for e in group]
        if not mapped:
            best_conf = max((e.confidence for e in group), default=0.0)
            modules = sorted({e.source_module for e in group if e.source_module})
            return ExternalKnown(UNCLASSIFIED, best_conf, True, f"{SLIPS_SOURCE}/{'+'.join(modules) or 'unknown'}", None, ids)
        best = max(mapped, key=lambda e: (e.confidence, e.threat_level))
        rejected = best.confidence < self.tau_k or best.threat_level < self.min_threat_weight
        technique = best.technique or next((e.technique for e in mapped if e.technique), None)
        return ExternalKnown(
            label=best.family or UNCLASSIFIED,
            score=best.confidence,
            rejected=rejected,
            source=f"{SLIPS_SOURCE}/{best.source_module or best.evidence_type.lower()}",
            technique=technique,
            evidence_ids=ids,
        )

    def anomaly_signal(self, group: Sequence[SlipsEvidence]) -> Optional[ExternalAnomaly]:
        sig = [e for e in group if e.is_anomaly_signal]
        if not sig:
            return None
        best = max(sig, key=lambda e: e.confidence)
        return ExternalAnomaly(score=best.confidence, high=True, source=f"{SLIPS_SOURCE}/{best.source_module or best.evidence_type.lower()}")

    def build_flow(self, key: Tuple[str, Optional[int]], group: Sequence[SlipsEvidence], known: ExternalKnown) -> FlowRecord:
        src, tw = key
        primary = next((e for e in group if e.family == known.label), group[0])
        # Missing volumetrics are None: has_required_fields() is then False and the internal
        # normality model is never asked to score a flow it cannot see (missing != normal).
        vol: Dict[str, Any] = {
            "bytes_in": None, "bytes_out": None, "pkts_in": None, "pkts_out": None, "duration_s": None, "mean_iat_ms": None,
            "conn_failures": 0.0, "short_window_conns": float(len(group)),
            "distinct_dst_ports": float(len({e.dst_port for e in group if e.dst_port is not None})),
        }
        if self.conn_index is not None:
            uids = sorted({u for e in group for u in e.uids})
            agg = self.conn_index.aggregate(uids)
            if agg:
                vol.update(agg)
        excerpt = " | ".join(f"[{e.evidence_type}] {e.description}" for e in group)[:4000]
        return FlowRecord(
            flow_id=f"slips:{src}:tw{tw if tw is not None else 'na'}",
            tenant=self.tenant,
            src_host=src,
            dst_ip=primary.target_ip or "0.0.0.0",
            dst_port=primary.dst_port or 0,
            bytes_in=vol["bytes_in"], bytes_out=vol["bytes_out"], pkts_in=vol["pkts_in"], pkts_out=vol["pkts_out"],
            duration_s=vol["duration_s"], mean_iat_ms=vol["mean_iat_ms"],
            conn_failures=vol["conn_failures"], short_window_conns=vol["short_window_conns"],
            distinct_dst_ports=vol["distinct_dst_ports"],
            login_failures=0.0,
            service_group=_service_group(primary.dst_port),
            observed_at=min((e.start_time for e in group if e.start_time), default=""),
            log_excerpt=excerpt,
        )

    def build_cases(self, parsed: SlipsParseResult) -> List[SlipsCase]:
        groups: Dict[Tuple[str, Optional[int]], List[SlipsEvidence]] = {}
        for e in parsed.evidence:
            groups.setdefault((e.source_ip, e.timewindow), []).append(e)
        by_evidence_id = {e.id: e for e in parsed.evidence}
        cases: List[SlipsCase] = []
        for key, group in groups.items():
            known = self.known_verdict(group)
            anomaly = self.anomaly_signal(group)
            flow = self.build_flow(key, group, known)
            ids = {e.id for e in group}
            incidents = [
                i for i in parsed.incidents
                if (i.source_ip == key[0] and i.timewindow == key[1]) or (ids & set(i.correl_ids))
            ]
            record = {
                "schema_version": "aisoc/slips-source-record/0.1",
                "evidence": [e.raw for e in group],
                "incidents": [i.raw for i in incidents],
                "unresolved_correl_ids": sorted({c for i in incidents for c in i.correl_ids if c not in by_evidence_id}),
            }
            cases.append(SlipsCase(flow, known, anomaly, list(group), incidents, record))
        cases.sort(key=lambda c: (c.flow.observed_at, c.flow.flow_id))
        return cases


@dataclass
class SlipsRunSummary:
    evidence: int
    incidents: int
    malformed: int
    cases: int
    slips_versions: List[str]
    status_counts: Dict[str, int]
    requires_human_review: int
    known_families: Dict[str, int]
    results: List[CaseResult] = field(default_factory=list)
    slips_cases: List[SlipsCase] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if k not in ("results", "slips_cases")}
        d["case_ids"] = [r.case_id for r in self.results]
        return d

    def export_cases(self) -> List[Dict[str, Any]]:
        """CaseResult dicts plus the flow identity fields and the Slips evidence ids behind each case."""
        out = []
        for r, c in zip(self.results, self.slips_cases):
            d = r.to_dict()
            d["flow"] = {"tenant": c.flow.tenant, "src_host": c.flow.src_host, "dst_ip": c.flow.dst_ip,
                         "dst_port": c.flow.dst_port, "observed_at": c.flow.observed_at, "service_group": c.flow.service_group}
            d["slips"] = {"evidence_ids": [e.id for e in c.evidence], "incident_ids": [i.id for i in c.incidents],
                          "known": c.known.__dict__, "anomaly": c.anomaly.__dict__ if c.anomaly else None,
                          "source_record_digest": digest(c.source_record)}
            out.append(d)
        return out


def run_slips_parsed(
    soc: AISOC,
    parsed: SlipsParseResult,
    tenant: str = "tenant-slips",
    conn_index: Optional[ZeekConnIndex] = None,
    use_internal_normality: bool = False,
    tau_k: float = 0.5,
    advance_clock_s: float = 7.0,
) -> SlipsRunSummary:
    adapter = SlipsAdapter(tenant, conn_index, tau_k=tau_k)
    cases = adapter.build_cases(parsed)
    results: List[CaseResult] = []
    status_counts: Dict[str, int] = {}
    families: Dict[str, int] = {}
    for c in cases:
        res = soc.ingest_external(c.flow, c.known, c.anomaly, use_internal_normality, c.source_record)
        results.append(res)
        status_counts[res.decision.status.value] = status_counts.get(res.decision.status.value, 0) + 1
        families[c.known.label] = families.get(c.known.label, 0) + 1
        soc.clock.advance(advance_clock_s)
    return SlipsRunSummary(
        evidence=len(parsed.evidence),
        incidents=len(parsed.incidents),
        malformed=parsed.malformed,
        cases=len(cases),
        slips_versions=sorted(parsed.slips_versions),
        status_counts=status_counts,
        requires_human_review=sum(1 for r in results if r.decision.requires_human_review),
        known_families=families,
        results=results,
        slips_cases=cases,
    )


def run_slips_alerts(
    soc: AISOC,
    alerts_path: Union[str, Path],
    tenant: str = "tenant-slips",
    conn_log: Optional[Union[str, Path]] = None,
    use_internal_normality: bool = False,
    tau_k: float = 0.5,
    advance_clock_s: float = 7.0,
) -> SlipsRunSummary:
    """Feed a Slips ``alerts.json`` through the SOC. Each (profile, time window) becomes one case."""
    parsed = read_alerts_json(alerts_path)
    index = ZeekConnIndex.load(conn_log) if conn_log else None
    return run_slips_parsed(soc, parsed, tenant, index, use_internal_normality, tau_k, advance_clock_s)


def sample_alerts_json_lines(injection_text: str = "") -> List[str]:
    """Small in-code IDMEFv2 sample in the exact shape Slips 1.1.x writes (for demos and scenarios).

    ``injection_text`` is appended to one ``Description`` to show that free text coming
    from the detector is treated as untrusted content.
    """

    def event(eid: str, etype: str, module: str, tl: str, conf: float, desc: str, src: str, tw: int,
              uids: List[str], prio: str, target: str, dport: int) -> str:
        note = {"evidence_type": etype, "uids": uids, "accumulated_threat_level": 0, "threat_level": tl,
                "evidence_signal": "PAMP", "timewindow": tw, "source_module": module}
        rec = {
            "Version": "2.D.V03", "ID": eid, "Status": IDMEF_EVENT, "Priority": prio,
            "StartTime": f"2026-10-30T09:1{tw}:00.000Z", "CreateTime": "2026-10-30T09:20:00.000Z",
            "Confidence": conf, "Description": desc,
            "Analyzer": {"IP": "192.168.1.5", "Name": "Slips", "Model": "1.1.24", "Category": ["NIDS"],
                         "Data": ["Flow", "Network"], "Method": ["Heuristic"]},
            "Source": [{"IP": src, "Port": [], "Protocol": ["TCP"], "Note": json.dumps({"AS": {}, "rDNS": "", "SNI": ""})}],
            "Target": [{"IP": target, "Port": [dport]}],
            "Note": json.dumps(note),
        }
        return json.dumps(rec)

    c2_desc = "C&C channel, destination IP: 185.199.110.153 port: 443/tcp score: 0.9823" + (" " + injection_text if injection_text else "")
    lines = [
        event("ev-c2-0001", "COMMAND_AND_CONTROL_CHANNEL", "rnn_cc_detection", "high", 0.9, c2_desc, "10.0.0.23", 2,
              ["Cuid0001", "Cuid0002"], "High", "185.199.110.153", 443),
        event("ev-ti-0002", "THREAT_INTELLIGENCE_TO_BLACKLISTED_IP", "threat_intelligence", "high", 1.0,
              "connection to blacklisted IP 185.199.110.153. Source: feodotracker", "10.0.0.23", 2, ["Cuid0001"], "High",
              "185.199.110.153", 443),
        event("ev-ml-0003", "ANOMALOUS_FLOW", "flowmldetection", "low", 0.65,
              "Anomalous flow detected by ML model to 198.51.100.7:8443", "10.0.0.88", 4, ["Cuid0301"], "Low", "198.51.100.7", 8443),
        event("ev-yd-0004", "YOUNG_DOMAIN", "flowalerts", "low", 0.6,
              "Connection to a young domain: cdn-update-9f3a.top registered 3 days ago", "10.0.0.90", 5, ["Cuid0401"], "Low",
              "203.0.113.44", 80),
    ]
    incident = {
        "Version": "2.D.V03", "ID": "inc-0001", "Status": IDMEF_INCIDENT, "Priority": "High",
        "StartTime": "2026-10-30T09:12:00.000Z", "CreateTime": "2026-10-30T09:21:00.000Z",
        "Analyzer": {"IP": "192.168.1.5", "Name": "Slips", "Model": "1.1.24", "Category": ["NIDS"], "Data": ["Flow", "Network"], "Method": ["Heuristic"]},
        "Source": [{"IP": "10.0.0.23"}], "CorrelID": ["ev-c2-0001", "ev-ti-0002"],
        "Note": json.dumps({"accumulated_threat_level": 2.5, "accumulated_ratl": 2.5, "risk_level": "high", "timewindow": 2,
                            "EndTime": "2026-10-30T09:22:00.000Z"}),
    }
    return lines + [json.dumps(incident)]
