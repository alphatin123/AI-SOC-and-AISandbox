"""Bridge to the real OpenWorkProof package (pip install "openworkproof==1.4.0", Python 3.12).

STATUS: the OWPBackend below was written from the public signatures shown in the project's
article ("When AI Agents Ship Code") and was NOT executed in the environment that produced
this repo (no network, package not installable). Treat it as the integration point and run
it against the real package. The ReferenceBackend is fully tested.

How the real objects are built (WorkOrder, grants, receipts, checkpoint, signed request) is
NOT reproduced here: copy it from the repo, e.g. examples/human_agency_profile_v01.py and
tests/evidence-bundles/verify_evidence_bundle.py at tag v1.4.0.
"""
import importlib.util


def have_owp() -> bool:
    return importlib.util.find_spec("openworkproof") is not None


def commitment_fields(evidence_sha256: str, window_digest: str) -> dict:
    """Carry our commitments in SIGNED fields. A third-party study of OWP found the generic
    `metadata` envelope sits outside the signed commitment, so never bind anything there.
    Field names (WorkOrder.objective, AgentRequest.context_source_digest) come from that study."""
    return {"objective": f"aisoc-case:{evidence_sha256}",
            "context_source_digest": window_digest}


class OWPBackend:
    """Delegates authorization and bundle verification to the real library."""

    def __init__(self):
        from openworkproof import policy                              # noqa: WPS433
        from openworkproof.acceptance import verify_acceptance_bundle  # noqa: WPS433
        self._policy, self._verify = policy, verify_acceptance_bundle

    def authorize_tool_call(self, *, work_order, grants, receipts, signed_request,
                            arguments, execution_facts, checkpoint) -> bool:
        ctx = self._policy.derive_authorization_context(
            work_order=work_order, grants=grants, receipts=receipts, request=signed_request,
            arguments=arguments, execution_facts=execution_facts, checkpoint=checkpoint)
        return bool(self._policy.authorize_tool_call(ctx).allowed)

    def verify_acceptance(self, *, work_order, report, effective_grants, receipts,
                          committed_evidence, acceptance_receipt, public_keys):
        return self._verify(work_order=work_order, report=report, effective_grants=effective_grants,
                            receipts=receipts, committed_evidence=committed_evidence,
                            acceptance_receipt=acceptance_receipt, public_keys=public_keys)


def make_owp_hook(backend: OWPBackend, context_builder):
    """Plug into Executor(owp_hook=...). `context_builder(signed_decision)` must return the
    keyword arguments of OWPBackend.authorize_tool_call built from real OWP objects."""
    return lambda signed: backend.authorize_tool_call(**context_builder(signed))
