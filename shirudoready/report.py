"""Text and JSON output."""

import json

from . import SHIRUDO_COMMIT, __version__
from .host import FAIL

LABEL = {"ok": "OK", "fail": "FAIL", "warn": "WARN", "info": "INFO"}


def _lines(results, max_items):
    out = []
    for r in results:
        out.append(f"  {LABEL.get(r.status, r.status.upper()):<5} {r.name:<25} {r.detail}".rstrip())
        if r.status != "ok" and r.hint:
            out.append(f"  {'':<5} {'':<25} -> {r.hint}")
        shown = r.items if not max_items else r.items[:max_items]
        for item in shown:
            out.append(f"  {'':<5} {'':<25} - {item}")
        if len(shown) < len(r.items):
            out.append(f"  {'':<5} {'':<25} ... and {len(r.items) - len(shown)} more (--items 0 shows all)")
    return out


def verdict(target):
    failed = [r for r in target if r.status == FAIL]
    counted = [r for r in target if r.status != "info"]
    return not failed, len(failed), len(counted)


def text(kernel, target, conflicts, max_items=12, heading="Can this host be a Shirudo target?"):
    ready, failed, total = verdict(target)
    out = [f"shirudo-ready {__version__} (checks follow shirudo {SHIRUDO_COMMIT})", f"Kernel {kernel or 'unknown'}"]
    if target:
        out += ["", heading] + _lines(target, max_items)
    if conflicts is not None:
        out += ["", "What would stop working, or weaken, if it enforced?"]
        out += _lines(conflicts, max_items)
    if target:
        out += ["", "Verdict: " + ("ready: every target check passes." if ready else
                                   f"not ready: {failed} of {total} target checks fail.")]
    return "\n".join(out) + "\n"


def as_json(kernel, target, conflicts):
    ready, failed, total = verdict(target)
    doc = {"tool": "shirudo-ready", "version": __version__, "shirudo_commit": SHIRUDO_COMMIT,
           "kernel_release": kernel, "ready": ready, "failed": failed, "total": total,
           "target": [r.as_dict() for r in target]}
    if conflicts is not None:
        doc["conflicts"] = [r.as_dict() for r in conflicts]
    return json.dumps(doc, indent=2) + "\n"
