"""Command line entry point.

    python -m aisoc simulate --out demo-output/aisoc-run
    python -m aisoc verify demo-output/aisoc-run
    python -m aisoc slips-ingest <slips-output>/alerts.json [--conn-log <slips-output>/zeek_files/conn.log]
    python -m aisoc aisoc-bundle-verify bundle.json [--hmac-key KEY]
    python -m aisoc aisoc-push demo-output/slips-run --base-url http://localhost:8000 --token ... [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .canonical import digest
from .crypto import Clock, Ed25519Signer, TrustedKeys
from .idps import MODEL_RELEASE_ROLE, DualModel, release_model
from .sandbox import HeuristicStubAgent
from .scenarios import ALL_SCENARIOS
from .simulate import FAMILIES, detection_metrics, generate, summarize_requests
from .soc import AISOC

DISCLAIMER = (
    "All data is synthetic and all agents are deterministic stubs. Numbers describe this reference "
    "implementation only; they are not detection results on real traffic, not a security certification, "
    "and not evidence of zero-day immunity or unconditional containment."
)


def _train(seed: int, held_out: str | None = None) -> tuple[DualModel, Any]:
    ds = generate(seed=seed, held_out_family=held_out)
    model = DualModel.train(ds.train, ds.val, model_version=f"dual_model/synthetic-seed{seed}" + (f"-lofo-{held_out}" if held_out else ""))
    return model, ds


def cmd_simulate(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {"disclaimer": DISCLAIMER, "seed": args.seed}

    print("1/4 training dual_model on time-ordered synthetic split ...")
    model, ds = _train(args.seed)
    report["detection_time_split"] = detection_metrics(model, ds.test)

    print("2/4 leave-one-family-out ...")
    lofo: Dict[str, Any] = {}
    for fam in FAMILIES:
        m, d = _train(args.seed, held_out=fam)
        held = [f for f in d.test if f.family == fam]
        benign = [f for f in d.test if f.label == "benign"]
        metrics = detection_metrics(m, held + benign)
        lofo[fam] = {
            "recall_on_held_out_family": metrics["recall_by_family"].get(fam),
            "benign_fpr": metrics["benign_fpr_at_fixed_thresholds"],
            "status_counts_on_held_out": {k: v for k, v in metrics["status_counts"].items()},
        }
    report["leave_one_family_out"] = lofo

    print("3/4 running SOC pipeline with heuristic agent (model loaded through the signed release gate) ...")
    clock = Clock(start=Clock().now())
    soc, manifest = _release_and_load(model, ds, clock, report["detection_time_split"], lofo)
    report["model_release"] = manifest.payload
    _seed_synthetic_context(soc, ds.test[: args.max_cases], args.seed)
    n = 0
    for f in ds.test[: args.max_cases]:
        soc.ingest(f)
        clock.advance(7)  # avoid dedup collapsing everything onto one window
        n += 1
    soc.export(out)
    report["soc_run"] = {
        "cases": n,
        "investigated": sum(1 for r in soc.results if r.investigated),
        "deduplicated": sum(1 for r in soc.results if r.deduplicated),
        "requests": summarize_requests(soc.results),
        "verification_status_counts": _count(r.verification_status for r in soc.results if r.investigated),
        "acceptance_status_counts": _count(r.acceptance_status for r in soc.results if r.investigated),
        "ledger_entries": len(soc.ledger.entries),
        "witness_checkpoints": len(soc.witness.checkpoints()),
    }

    print("4/4 running security scenarios and ablations ...")
    scen: List[Dict[str, Any]] = []
    for fn in ALL_SCENARIOS:
        r = fn(model)
        scen.append(r)
        print(f"   [{'ok' if r['passed'] else 'FAIL'}] {r['name']}")
    report["scenarios"] = scen

    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True, default=str))
    (out / "report.md").write_text(_markdown(report))
    print(f"\nwritten to {out}/report.json and report.md")
    return 0 if all(s["passed"] for s in scen) else 1


def _release_and_load(model: DualModel, ds: Any, clock: Clock, metrics: Dict[str, Any], lofo: Dict[str, Any]) -> tuple[AISOC, Any]:
    """Training-domain step: sign a release manifest; inference-domain step: load only if it verifies."""
    release_signer = Ed25519Signer(MODEL_RELEASE_ROLE)
    trust = TrustedKeys()
    trust.trust(release_signer)
    dataset_digest = digest([f.__dict__ for f in ds.train])
    evaluation = {
        "benign_fpr": metrics["benign_fpr_at_fixed_thresholds"],
        "recall_by_family": metrics["recall_by_family"],
        "lofo_recall": {fam: v["recall_on_held_out_family"] for fam, v in lofo.items()},
    }
    manifest = release_model(model, dataset_digest, release_signer, clock, approved_by="simulated-release-board", evaluation=evaluation)
    soc = AISOC.from_release(model.to_bytes(), manifest, trust, HeuristicStubAgent(clock), clock=clock)
    return soc, manifest


def cmd_slips_ingest(args: argparse.Namespace) -> int:
    """Run Slips alerts.json (IDMEFv2) through the SOC as the external known/anomaly branch."""
    from .adapters.slips import run_slips_alerts

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    print("training dual_model on synthetic data (only its release gate and thresholds are used; the internal "
          f"normality model is {'ENABLED' if args.internal_normality else 'disabled'} for real traffic) ...")
    model, ds = _train(args.seed)
    clock = Clock(start=Clock().now())
    metrics = detection_metrics(model, ds.test)
    soc, manifest = _release_and_load(model, ds, clock, metrics, {})
    summ = run_slips_alerts(soc, args.alerts, tenant=args.tenant, conn_log=args.conn_log,
                            use_internal_normality=args.internal_normality, tau_k=args.tau_k)
    soc.export(out)
    cases = summ.export_cases()
    summary = {"disclaimer": DISCLAIMER + " Slips confidences are not calibrated probabilities; tau_k is a deployment setting.",
               "source": {"alerts": str(args.alerts), "conn_log": str(args.conn_log) if args.conn_log else None,
                          "slips_versions": summ.slips_versions},
               "model_release": manifest.payload, **summ.to_dict(), "case_results": cases}
    (out / "slips-summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str))
    print(json.dumps({k: summary[k] for k in ("evidence", "incidents", "malformed", "cases", "status_counts", "requires_human_review", "known_families")}, indent=2))
    print(f"\nwritten to {out}/ (ledger.json, witness-checkpoints.json, slips-summary.json); verify with: python -m aisoc verify {out}")
    return 0


def cmd_aisoc_bundle_verify(args: argparse.Namespace) -> int:
    from .adapters.aisoc_stack import AiSOCBundleError, verify_aisoc_bundle

    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    try:
        check = verify_aisoc_bundle(bundle, args.hmac_key)
    except AiSOCBundleError as exc:
        print(json.dumps({"ok": False, "problems": [str(exc)]}, indent=2))
        return 1
    print(json.dumps(check.to_dict(), indent=2))
    if check.ok and not check.hmac_checked:
        print("note: only payload_sha256 was checked (no --hmac-key). sha256 alone detects accidental corruption, not forgery.", file=sys.stderr)
    return 0 if check.ok else 1


def cmd_aisoc_push(args: argparse.Namespace) -> int:
    """Push the cases of an exported run (from slips-ingest or simulate) to AiSOC as alerts."""
    from .adapters.aisoc_stack import AiSOCClient, AiSOCConfig, AiSOCError, case_to_event, idempotency_key_for
    from .soc import CaseResult

    d = Path(args.run_dir)
    summary_path = d / "slips-summary.json"
    if not summary_path.exists():
        print(f"{summary_path} not found; aisoc-push currently consumes slips-ingest output", file=sys.stderr)
        return 2
    summary = json.loads(summary_path.read_text())
    entries = json.loads((d / "ledger.json").read_text())
    cps = json.loads((d / "witness-checkpoints.json").read_text())
    head = entries[-1]["entry_hash"] if entries else None
    root = cps[-1]["payload"]["merkle_root"] if cps else None
    events = []
    for c in summary["case_results"]:
        res = CaseResult.from_dict(c)
        flow = _flow_stub(c)
        technique = (c.get("slips") or {}).get("known", {}).get("technique")
        events.append(case_to_event(res, flow, head, root, techniques=[technique] if technique else None))
    if args.dry_run:
        print(json.dumps({"would_post": f"{args.base_url.rstrip('/')}/api/v1/alerts/submit", "events": events}, indent=2, default=str))
        return 0
    if not args.token:
        print("--token (or AISOC_TOKEN) is required unless --dry-run", file=sys.stderr)
        return 2
    client = AiSOCClient(AiSOCConfig(base_url=args.base_url, token=args.token, ingest_url=args.ingest_url))
    ok = 0
    for ev, c in zip(events, summary["case_results"]):
        try:
            if args.ingest_url:
                resp = client.ingest_batch([ev])
            else:
                resp = client.submit_alert([ev], ev["title"], ev["description"], ev["severity"], ev["tags"],
                                           idempotency_key=idempotency_key_for(CaseResult.from_dict(c)))
            ok += 1
            print(f"[ok] {c['case_id']} -> {resp.get('id', resp)}")
        except AiSOCError as exc:
            print(f"[FAIL] {c['case_id']}: {exc}", file=sys.stderr)
    return 0 if ok == len(events) else 1


def _flow_stub(case: Dict[str, Any]):
    """Rebuild the few FlowRecord fields the AiSOC event needs from an exported case dict."""
    from .idps import FlowRecord

    f = case.get("flow", {})
    return FlowRecord(flow_id=case["flow_id"], tenant=f.get("tenant", ""), src_host=f.get("src_host", ""), dst_ip=f.get("dst_ip", ""),
                      dst_port=int(f.get("dst_port", 0) or 0), bytes_in=0, bytes_out=0, pkts_in=0, pkts_out=0, duration_s=0,
                      mean_iat_ms=0, conn_failures=0, short_window_conns=0, distinct_dst_ports=0, login_failures=0,
                      observed_at=f.get("observed_at", ""))


def cmd_verify(args: argparse.Namespace) -> int:
    """Offline re-verification of an exported run: chain, witness, receipts."""
    from .canonical import digest
    from .crypto import TrustedKeys
    from .owp.ledger import GENESIS, merkle_root

    d = Path(args.dir)
    entries = json.loads((d / "ledger.json").read_text())
    keys = json.loads((d / "trusted-keys.json").read_text())
    cps = json.loads((d / "witness-checkpoints.json").read_text())
    receipts = json.loads((d / "tool-side-receipts.json").read_text())
    trusted = TrustedKeys()
    for kid, info in keys.items():
        trusted.trust_raw(kid, info["role"], bytes.fromhex(info["public_raw_hex"]))

    problems: List[str] = []
    prev = GENESIS
    for i, e in enumerate(entries):
        body = {k: e[k] for k in e if k != "entry_hash"}
        if e["prev_hash"] != prev or digest(body) != e["entry_hash"] or e["index"] != i:
            problems.append(f"chain broken at {i}")
        prev = e["entry_hash"]
    hashes = [e["entry_hash"] for e in entries]
    for cp in cps:
        p = cp["payload"]
        if not any(trusted.verify(p, s, expected_role="ledger") for s in cp["signatures"]):
            problems.append("checkpoint signature invalid")
        elif p["length"] > len(hashes):
            problems.append(f"truncated below witnessed length {p['length']}")
        elif merkle_root(hashes[: p["length"]]) != p["merkle_root"]:
            problems.append(f"merkle mismatch at witnessed length {p['length']}")
    egress_seen: Dict[str, int] = {}
    for e in entries:
        if e["entry_type"] == "agent_egress":
            egress_seen.setdefault(e["refs"].get("msg_digest", ""), e["index"])
        elif e["entry_type"] == "action_request":
            idx = egress_seen.get(e["object_digest"])
            if idx is None or idx > e["index"]:
                problems.append(f"entry {e['index']}: action_request without a prior audited egress record")
    recorded = {e["object_digest"] for e in entries if e["entry_type"] == "action_receipt"}
    authorized = {e["refs"].get("request_digest") for e in entries if e["entry_type"] == "authorization"}
    for r in receipts:
        p = r["payload"]
        if not any(trusted.verify(p, s, expected_role="executor") for s in r["signatures"]):
            problems.append(f"receipt {p['receipt_id']} signature invalid")
        if p["outcome"] == "executed" and (digest(p) not in recorded or p["request_digest"] not in authorized):
            problems.append(f"receipt {p['receipt_id']} executed without ledger authorization (bypass)")

    status = "FAILED" if problems else ("UNKNOWN" if not cps else "VERIFIED")
    print(json.dumps({"status": status, "entries": len(entries), "checkpoints": len(cps), "receipts": len(receipts), "problems": problems}, indent=2))
    return 0 if status == "VERIFIED" else 1


def _seed_synthetic_context(soc: AISOC, flows, seed: int) -> None:
    """Give the read-only tools something to correlate: a synthetic IOC feed and host windows."""
    import random

    rng = random.Random(seed)
    for f in flows:
        if f.label != "benign" and rng.random() < 0.5:
            soc.telemetry.ioc[f.dst_ip] = {"indicator": f.dst_ip, "match": True, "source": "synthetic-feed"}
        soc.telemetry.host_windows[f"{f.tenant}/{f.src_host}"] = {
            "new_process_count": rng.randint(25, 60) if f.label != "benign" else rng.randint(0, 10),
            "window_s": 300,
        }


def _count(it) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for x in it:
        out[str(x)] = out.get(str(x), 0) + 1
    return out


def _markdown(r: Dict[str, Any]) -> str:
    lines = ["# AI SOC reference run", "", f"> {r['disclaimer']}", ""]
    dt = r["detection_time_split"]
    lines += ["## Detection (time-ordered split, synthetic)", "",
              f"- benign FPR at validation-fixed thresholds: {dt['benign_fpr_at_fixed_thresholds']}",
              f"- recall by family: {dt['recall_by_family']}", f"- status mix: {dt['status_counts']}", "",
              "## Leave-one-family-out", "", "| held-out family | recall | benign FPR |", "|---|---|---|"]
    for fam, v in r["leave_one_family_out"].items():
        lines.append(f"| {fam} | {v['recall_on_held_out_family']} | {v['benign_fpr']} |")
    s = r["soc_run"]
    lines += ["", "## SOC run", "", f"- cases: {s['cases']}, investigated: {s['investigated']}, dedup-suppressed: {s['deduplicated']}",
              f"- requests: {s['requests']}", f"- verification: {s['verification_status_counts']}",
              f"- acceptance: {s['acceptance_status_counts']}", f"- ledger entries: {s['ledger_entries']}, witnessed checkpoints: {s['witness_checkpoints']}",
              "", "## Scenarios and ablations", "", "| result | scenario | expected |", "|---|---|---|"]
    for sc in r["scenarios"]:
        lines.append(f"| {'ok' if sc['passed'] else 'FAIL'} | {sc['name']} | {sc['expected']} |")
    return "\n".join(lines) + "\n"


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="aisoc")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("simulate", help="train dual_model, run the SOC pipeline, scenarios and ablations")
    s.add_argument("--out", default="demo-output/aisoc-run")
    s.add_argument("--seed", type=int, default=1)
    s.add_argument("--max-cases", type=int, default=200)
    s.set_defaults(fn=cmd_simulate)
    v = sub.add_parser("verify", help="offline verification of an exported run directory")
    v.add_argument("dir")
    v.set_defaults(fn=cmd_verify)
    si = sub.add_parser("slips-ingest", help="run a Slips alerts.json (IDMEFv2) through the SOC as the external detector branch")
    si.add_argument("alerts", help="path to Slips <output>/alerts.json")
    si.add_argument("--conn-log", default=None, help="Zeek conn.log from the same Slips output dir (adds flow volumetrics)")
    si.add_argument("--tenant", default="tenant-slips")
    si.add_argument("--out", default="demo-output/slips-run")
    si.add_argument("--seed", type=int, default=1)
    si.add_argument("--tau-k", type=float, default=0.5, help="min Slips confidence for the known branch to accept a class")
    si.add_argument("--internal-normality", action="store_true",
                    help="score real flows with the synthetic-trained normality model (only meaningful after retraining on your own baseline)")
    si.set_defaults(fn=cmd_slips_ingest)
    bv = sub.add_parser("aisoc-bundle-verify", help="re-derive the integrity fields of an AiSOC investigation bundle")
    bv.add_argument("bundle")
    bv.add_argument("--hmac-key", default=None, help="AiSOC bundle signing key; without it only payload_sha256 is checked")
    bv.set_defaults(fn=cmd_aisoc_bundle_verify)
    ap_push = sub.add_parser("aisoc-push", help="submit the cases of an exported slips-ingest run to AiSOC as alerts")
    ap_push.add_argument("run_dir")
    ap_push.add_argument("--base-url", default="http://localhost:8000")
    ap_push.add_argument("--token", default=__import__("os").environ.get("AISOC_TOKEN", ""))
    ap_push.add_argument("--ingest-url", default=None, help="use the streaming ingest endpoint (e.g. http://localhost:8081/v1/ingest/batch) instead of alerts/submit")
    ap_push.add_argument("--dry-run", action="store_true", help="print the events that would be posted; no network")
    ap_push.set_defaults(fn=cmd_aisoc_push)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
