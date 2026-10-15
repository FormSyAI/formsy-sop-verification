"""Disclosure for retained model prose, separate from evidence-based judgments."""


def annotate_model_reasons(value):
    """Mark new report narratives without binding them to the row's target versions.

    The original model_reason, accepted reason, results and evidence remain intact.
    Raw provider artifacts are not passed here. This label supplies no semantic
    proof; accepted judgments still require their existing object/version gates.
    """
    if isinstance(value, dict):
        if isinstance(value.get("model_reason"), str) and value["model_reason"].strip():
            value["model_reason_verification"] = {
                "kind": "raw_model_narrative", "facts": "unverified",
                "version_binding": "unverified", "decision_basis": False,
            }
        for child in value.values():
            annotate_model_reasons(child)
    elif isinstance(value, list):
        for child in value:
            annotate_model_reasons(child)
    return value
