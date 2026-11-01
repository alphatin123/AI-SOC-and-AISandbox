"""Command line entry point.

    python -m aisoc simulate --out demo-output/aisoc-run
    python -m aisoc verify demo-output/aisoc-run
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .crypto import Clock
from .idps import DualModel
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

    print("3/4 running SOC pipeline with heuristic agent ...")
    clock = Clock(start=Clock().now())
    soc = AISOC(model, HeuristicStubAgent(clock), clock=clock)
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
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
