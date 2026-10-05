"""Seeded-fault (mutation) probe -- referee analysis A3, closes M1's
execution-evidence gap for an uncovered oracle rule.

Method: build a mutant copy of python-tuf 7.0.0 with a single-line defect
in one security check, run this study's own already-validated pilot
scenario for the property that check enforces, and confirm the oracle
(engine-predicted trace vs observed trace) flips from CONFORMING to
NORMATIVE_VIOLATION -- while the two unmutated implementations, run through
the identical harness in the same session, stay CONFORMING.

Mutations:
  M1  P2 / ROOT_ROTATE_SKIP   (NO independent official-test evidence -- the
      target of this analysis): trusted_metadata_set.update_root's
      `new_root.version != self.root.version + 1` weakened to `< ... + 1`,
      so a v1->v3 root version skip is accepted.
  M2  P3 / TIMESTAMP_REPLAY    (HAS independent evidence -- included as a
      positive control that the probe method itself detects a known class):
      the timestamp rollback check `new_timestamp.version <
      self.timestamp.version` disabled.

Nothing here is fabricated: every decision below is a real subprocess run
of a real client (mutant or stock) via tuf-conformance's ClientRunner.
"""
import os
import shutil
import sys
import tempfile

CONF = os.environ.get("TUF_STUDY_EXPERIMENT_DIR",
                      os.path.expanduser("~/tuf_experiment_macos")) + "/tuf-conformance"
sys.path.insert(0, CONF)
from tuf_conformance._internal.client_runner import ClientRunner  # noqa: E402
from tuf_conformance._internal.simulator_server import SimulatorServer  # noqa: E402
from tuf.api.metadata import Root, Snapshot, Targets, Timestamp  # noqa: E402

VENV_PY = CONF + "/env/bin/python"
STOCK_TUF = os.path.dirname(__import__(
    "importlib").util.find_spec("tuf").origin) if False else None
# resolve stock tuf dir via the venv python (the interpreter python_tuf.py uses
# is /opt/anaconda3/bin/python -- same pinned tuf==7.0.0)
import subprocess  # noqa: E402
STOCK_TUF = subprocess.check_output(
    ["python", "-c", "import tuf,os;print(os.path.dirname(tuf.__file__))"],
    text=True).strip()
TMS_REL = "ngclient/_internal/trusted_metadata_set.py"

MUTATIONS = {
    "M1_P2_root_skip": (
        "        if new_root.version != self.root.version + 1:",
        "        if new_root.version < self.root.version + 1:  # SEEDED FAULT",
    ),
    "M2_P3_ts_rollback": (
        "            if new_timestamp.version < self.timestamp.version:",
        "            if False and new_timestamp.version < self.timestamp.version:  # SEEDED FAULT",
    ),
    # P4 / METADATA_BY_REMOVED_KEY (NO independent evidence): disable the
    # currently-trusted-root's verification of a NEW root for the root role,
    # so a version signed only by a since-removed key is no longer caught by
    # the old-threshold check (spec Sec.5.3.4 clause (1)).
    "M3_P4_removed_key": (
        "    if delegator:\n        if role_name is None:\n            role_name = role.type\n\n        delegator.verify_delegate(role_name, md.signed_bytes, md.signatures)",
        "    if delegator and role is not Root:  # SEEDED FAULT\n        if role_name is None:\n            role_name = role.type\n\n        delegator.verify_delegate(role_name, md.signed_bytes, md.signatures)",
    ),
}


def make_mutant(name):
    d = tempfile.mkdtemp(prefix=f"mutant_{name}_")
    dst = os.path.join(d, "tuf")
    shutil.copytree(STOCK_TUF, dst)
    p = os.path.join(dst, TMS_REL)
    src = open(p).read()
    old, new = MUTATIONS[name]
    assert old in src, f"anchor not found for {name}"
    open(p, "w").write(src.replace(old, new, 1))
    # entrypoint that prepends the mutant dir -- keep the stock shebang on
    # line 1 (ClientRunner execs the script directly), inject sys.path after.
    entry = os.path.join(d, "python_tuf_mutant.py")
    lines = open(CONF + "/clients/python-tuf/python_tuf.py").read().split("\n")
    assert lines[0].startswith("#!"), lines[0]
    lines.insert(1, "import sys as _s; _s.path.insert(0, %r)" % d)
    open(entry, "w").write("\n".join(lines))
    os.chmod(entry, 0o755)
    return d, entry


def p2_scenario(entry):
    """v1 -> serve v3 (skip v2), SAME root keys, so the *only* gate is the
    sequential-version check (`new_root.version != self.root.version + 1`,
    spec Sec.5.3.5) -- this isolates the ROOT_ROTATE_SKIP rule from the
    dual-threshold rule the study's own p2_case also happens to trip via
    rotate_keys(). Spec-correct: baseline ACCEPT(0), skip REJECT(1)."""
    srv = SimulatorServer("mut")
    init_data, repo = srv.new_test("mut")
    c = ClientRunner(entry, srv, "mut")
    assert c.init_client(init_data) == 0
    a = c.refresh(init_data)                       # baseline (SETUP)
    repo.root.version += 1                         # -> declared v3, keys unchanged
    repo.publish([Root.type], verify_version=False)  # v1 -> v3 directly
    b = c.refresh(init_data)                       # ROOT_ROTATE_SKIP decision
    return {"baseline_refresh": a, "refresh_after_skip_v1_to_v3": b}


def p3_scenario(entry):
    """advance timestamp to v2, then serve v1 again. Expect: advance ACCEPT,
    replay REJECT."""
    srv = SimulatorServer("mut")
    init_data, repo = srv.new_test("mut")
    c = ClientRunner(entry, srv, "mut")
    c.init_client(init_data)
    repo.publish([Timestamp.type])                 # v2
    a = c.refresh(init_data)
    del repo.signed_mds[Timestamp.type]
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])                 # replay v1 (as v3 publish slot)
    b = c.refresh(init_data)
    return {"advance_refresh": a, "refresh_after_replay": b}


STOCK_PYTUF = CONF + "/clients/python-tuf/python_tuf.py"
GOTUF = CONF + "/clients/go-tuf/go-tuf"
TUFJS = os.path.dirname(CONF) + "/tuf-js/tuf-conformance-entrypoint.js"

import json  # noqa: E402
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_full_pair_matrix_macos import (  # noqa: E402
    ExecState, do_ROOT_ROTATE_VALID, _manual_publish)


def p4_scenario(entry):
    """valid dual-signed rotation v1->v2 (removes v1 key K), then a v3 that
    RE-DECLARES K as an authorized root key and is signed only by K -- a
    "resurrect the revoked key" attack. Stock clients REJECT because v3 is
    not also signed by a threshold of the currently-trusted (v2) keys
    (spec Sec.5.3.4 clause (1), enforced by the trusted root's own
    verify_delegate). The M3 mutation disables exactly that clause for the
    root role. Key: refresh_v3_resurrects_removed_key."""
    srv = SimulatorServer("mut")
    init_data, repo = srv.new_test("mut")
    c = ClientRunner(entry, srv, "mut")
    assert c.init_client(init_data) == 0
    st = ExecState(repo)
    a = do_ROOT_ROTATE_VALID(repo, c, init_data, st, False)     # v1 -> v2 valid; K removed
    removed = list(st.root_removed_signers.values())            # the revoked key(s)
    # v3: put the revoked key back in the declared key set, sign ONLY with it
    for s in removed:
        repo.root.add_key(s.public_key, Root.type)
    b = _publish_and_refresh(repo, c, init_data, removed)
    return {"valid_rotation_v2": a, "refresh_v3_resurrects_removed_key": b}


def _publish_and_refresh(repo, c, init_data, signers):
    _manual_publish(repo, Root.type, signers, replace_current=False)
    return c.refresh(init_data)


# engine-predicted decision for the payload step of each probe (from
# analysis/state_engine.py's rule table): all REJECT.
PREDICTED = {"M1_P2_root_skip": 1, "M2_P3_ts_rollback": 1, "M3_P4_removed_key": 1}
RULE = {"M1_P2_root_skip": "ROOT_ROTATE_SKIP  (P2; NO independent official evidence -- probe target)",
        "M2_P3_ts_rollback": "TIMESTAMP_REPLAY  (P3; HAS independent evidence -- method positive control)",
        "M3_P4_removed_key": "METADATA_BY_REMOVED_KEY  (P4; NO independent official evidence -- probe target)"}

print("STOCK tuf pkg:", STOCK_TUF)
print()
out = []
for mut, scen, key in [
    ("M1_P2_root_skip", p2_scenario, "refresh_after_skip_v1_to_v3"),
    ("M2_P3_ts_rollback", p3_scenario, "refresh_after_replay"),
    ("M3_P4_removed_key", p4_scenario, "refresh_v3_resurrects_removed_key"),
]:
    pred = PREDICTED[mut]
    print(f"===== {mut} =====")
    print(f"  rule under test : {RULE[mut]}")
    print(f"  engine predicts : {key} -> REJECT ({pred})")
    rec = {"mutation": mut, "rule": RULE[mut], "engine_predicted": pred, "step": key}
    for name, ep in [("python-tuf", STOCK_PYTUF), ("go-tuf-v2", GOTUF), ("tuf-js", TUFJS)]:
        r = scen(ep)
        obs = r[key]
        verdict = "CONFORMING" if obs == pred else "NORMATIVE_VIOLATION"
        rec[f"stock_{name}"] = {"trace": r, "observed": obs, "verdict": verdict}
        print(f"  stock {name:<11}: {key}={obs}  -> {verdict}")
    d, entry = make_mutant(mut)
    r = scen(entry); obs = r[key]
    verdict = "CONFORMING" if obs == pred else "NORMATIVE_VIOLATION"
    rec["mutant_python-tuf"] = {"trace": r, "observed": obs, "verdict": verdict}
    print(f"  MUTANT python-tuf: {key}={obs}  -> {verdict}   <== seeded fault")
    shutil.rmtree(d, ignore_errors=True)
    out.append(rec)
    print()

dst = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "example_data", "MUTATION_PROBE_results.json")
json.dump(out, open(dst, "w"), indent=2)
print("wrote", dst)
