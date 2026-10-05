# AUTO-DERIVED macOS variant of run_full_pair_matrix.py (referee A7 / cross-platform).
# Only the 3 client entrypoints and the 2 output filenames differ; case logic identical.
"""
FULL reachable ordered-pair mechanical execution -- all 52 pairs the
12-transition state_engine.py enumerates at depth 2, not a hand-picked or
sub-alphabet-restricted subset. Executed against all three real client
implementations: python-tuf 7.0.0, go-tuf v2.4.2, tuf-js.

This supersedes run_mechanical_root_pairs.py's 10-pair, 4-transition-
sub-alphabet batch (kept for provenance, not deleted) per explicit user
direction to attempt the full reachable-pair space rather than stopping at
the root-rotation sub-alphabet.

Before writing this script, THREE properties of cross-transition
interaction were verified empirically (not assumed) via
probe_cross_role_blocking{,2,3}.py, because a naive per-transition-
independent executor would have silently produced wrong predictions for a
large fraction of the 52 pairs:

  1. A client whose root is stuck on an invalid, not-yet-superseded version
     (after ROOT_ROTATE_SKIP / ROOT_ROTATE_INSUF_THRESHOLD /
     METADATA_BY_REMOVED_KEY, unrecovered) REJECTs EVERY subsequent refresh
     attempt, not just further root attempts -- confirmed for
     TIMESTAMP_ADVANCE specifically, both real clients.
  2. An expired-metadata REJECT (EXPIRE) is similarly persistent -- it does
     NOT self-heal even when the affected role is republished normally
     afterward, because the `expires` field itself is what's wrong, not
     the version ordering.
  3. In sharp contrast, TIMESTAMP_REPLAY / SNAPSHOT_REPLAY's REJECT DOES
     self-heal on the very next ordinary publish of that same role (a
     version-ordering problem, not a persistent-field problem) -- verified
     for both directly-following-role and unrelated-following-role cases.

state_engine.py was corrected accordingly (root_blocked / expired fields,
global blocking override in apply_transition) BEFORE this script was
written, so the predictions it produces below already reflect this.

CONSTRUCTION RULE FOLLOWED THROUGHOUT: every pair's second step is
constructed as a FULLY REAL, independently-valid attempt at that
transition -- never skipped, never faked -- even when the engine predicts
it will fail due to a blocked/expired precondition from step one. What
actually happens is observed, not assumed.
"""
import json
import os
import sys

EXPERIMENT_DIR = os.environ.get("TUF_STUDY_EXPERIMENT_DIR", r"C:\Users\yasemin.bozkurt\tuf_experiment")
REPO_DIR = os.environ.get("TUF_STUDY_REPO_DIR", r"C:\Users\yasemin.bozkurt\Desktop\new\tuf_study")
CONFORMANCE_DIR = os.path.join(EXPERIMENT_DIR, "tuf-conformance")

sys.path.insert(0, CONFORMANCE_DIR)
sys.path.insert(0, os.path.join(REPO_DIR, "analysis"))

from tuf.api.metadata import Root, Snapshot, Timestamp, Targets, DelegatedRole, MetaFile
from tuf.api.serialization.json import JSONSerializer
from tuf_conformance._internal import utils
from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer

import tstm_analysis as pl
import state_engine as engine

PYTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "python-tuf", "python_tuf.py")
GOTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "go-tuf", "go-tuf")
TUFJS_ENTRY = os.path.join(EXPERIMENT_DIR, "tuf-js", "tuf-conformance-entrypoint.js")
IMPLS = {"python-tuf": PYTUF_ENTRY, "go-tuf-v2": GOTUF_ENTRY, "tuf-js": TUFJS_ENTRY}

_delegation_counter = [0]  # unique role name per pair, avoids any cross-test collision


class ExecState:
    def __init__(self, repo):
        self.root_current_signers = dict(repo.signers[Root.type])
        self.root_removed_signers: dict | None = None
        self.delegation_role_name: str | None = None


def _manual_publish(repo, role, signers: list, replace_current: bool = False) -> None:
    """Generic version of the replace-aware manual publish proven in
    run_mechanical_root_pairs.py, extended to any role (not just Root)."""
    md = repo.mds[role]
    lst = repo.signed_mds.setdefault(role, [])
    if replace_current and lst:
        md.signed.version = len(lst)
    else:
        md.signed.version += 1
    md.signatures.clear()
    for s in signers:
        md.sign(s, append=True)
    encoded = md.to_bytes(JSONSerializer())
    if replace_current and lst:
        lst[-1] = encoded
    else:
        lst.append(encoded)


# ---------------------------------------------------------------------------
# One executor per transition type. Each: (repo, client, init_data, state,
# root_blocked: bool) -> observed exit code (0=ACCEPT, 1=REJECT).
# `root_blocked` is passed in so ROOT_ROTATE_VALID knows whether it must
# replace-in-place (Section 5's proven fix) or may append normally -- this
# is a fact about EXECUTION MECHANICS the abstract engine doesn't need to
# expose, but the concrete simulator does.
# ---------------------------------------------------------------------------

def do_ROOT_ROTATE_VALID(repo, client, init_data, state, root_blocked):
    new_signer = repo.new_signer()
    repo.root.add_key(new_signer.public_key, Root.type)
    repo.root.roles[Root.type].keyids.clear()
    repo.root.add_key(new_signer.public_key, Root.type)
    _manual_publish(repo, Root.type, list(state.root_current_signers.values()) + [new_signer],
                     replace_current=root_blocked)
    rc = client.refresh(init_data)
    if rc == 0:
        state.root_removed_signers = state.root_current_signers
        state.root_current_signers = {new_signer.public_key.keyid: new_signer}
    return rc


def do_ROOT_ROTATE_SKIP(repo, client, init_data, state, root_blocked):
    if not root_blocked:
        repo.root.version += 1
    repo.rotate_keys(Root.type)
    _manual_publish(repo, Root.type, list(repo.signers[Root.type].values()), replace_current=root_blocked)
    return client.refresh(init_data)


def do_ROOT_ROTATE_INSUF_THRESHOLD(repo, client, init_data, state, root_blocked):
    new_signer = repo.new_signer()
    repo.root.roles[Root.type].keyids.clear()
    repo.root.add_key(new_signer.public_key, Root.type)
    _manual_publish(repo, Root.type, [new_signer], replace_current=root_blocked)
    return client.refresh(init_data)


def do_METADATA_BY_REMOVED_KEY(repo, client, init_data, state, root_blocked):
    assert state.root_removed_signers is not None, "precondition violated: no prior valid rotation"
    _manual_publish(repo, Root.type, list(state.root_removed_signers.values()), replace_current=root_blocked)
    return client.refresh(init_data)


def do_TIMESTAMP_ADVANCE(repo, client, init_data, state, root_blocked):
    repo.publish([Timestamp.type])
    return client.refresh(init_data)


def do_TIMESTAMP_REPLAY(repo, client, init_data, state, root_blocked):
    del repo.signed_mds[Timestamp.type]
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])
    rc = client.refresh(init_data)
    repo.publish([Timestamp.type])  # self-heal (SETUP, not counted) -- see module docstring finding (3)
    client.refresh(init_data)
    return rc


def do_SNAPSHOT_ADVANCE(repo, client, init_data, state, root_blocked):
    repo.publish([Snapshot.type, Timestamp.type])
    return client.refresh(init_data)


def do_SNAPSHOT_REPLAY(repo, client, init_data, state, root_blocked):
    del repo.signed_mds[Snapshot.type]
    repo.snapshot.version = 1
    repo.publish([Snapshot.type, Timestamp.type])
    rc = client.refresh(init_data)
    repo.publish([Snapshot.type, Timestamp.type])  # self-heal (SETUP, not counted)
    client.refresh(init_data)
    return rc


def do_DELEGATION_CREATE(repo, client, init_data, state, root_blocked):
    _delegation_counter[0] += 1
    name = f"delegated{_delegation_counter[0]}"
    state.delegation_role_name = name
    role = DelegatedRole(name, [], 1, False, [f"{name}path/*"])
    delegated_targets = Targets(expires=repo.safe_expiry)
    repo.add_delegation(Targets.type, role, delegated_targets)
    repo.publish([name, Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])
    return client.refresh(init_data)


def do_DELEGATION_REMOVE(repo, client, init_data, state, root_blocked):
    assert state.delegation_role_name is not None, "precondition violated: no prior delegation"
    del repo.targets.delegations.roles[state.delegation_role_name]
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    return client.refresh(init_data)


def do_DELEGATED_REPLAY_AFTER_REMOVAL(repo, client, init_data, state, root_blocked):
    assert state.delegation_role_name is not None
    return client.download_target(init_data, f"{state.delegation_role_name}path/foo")


def do_EXPIRE(repo, client, init_data, state, root_blocked):
    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.publish([Timestamp.type])
    return client.refresh(init_data)  # deliberately NOT self-healed -- see finding (2)


EXECUTORS = {
    "ROOT_ROTATE_VALID": do_ROOT_ROTATE_VALID,
    "ROOT_ROTATE_SKIP": do_ROOT_ROTATE_SKIP,
    "ROOT_ROTATE_INSUF_THRESHOLD": do_ROOT_ROTATE_INSUF_THRESHOLD,
    "METADATA_BY_REMOVED_KEY": do_METADATA_BY_REMOVED_KEY,
    "TIMESTAMP_ADVANCE": do_TIMESTAMP_ADVANCE,
    "TIMESTAMP_REPLAY": do_TIMESTAMP_REPLAY,
    "SNAPSHOT_ADVANCE": do_SNAPSHOT_ADVANCE,
    "SNAPSHOT_REPLAY": do_SNAPSHOT_REPLAY,
    "DELEGATION_CREATE": do_DELEGATION_CREATE,
    "DELEGATION_REMOVE": do_DELEGATION_REMOVE,
    "DELEGATED_REPLAY_AFTER_REMOVAL": do_DELEGATED_REPLAY_AFTER_REMOVAL,
    "EXPIRE": do_EXPIRE,
}

# sequence_corpus.schema.json's `family` enum is F1-F7 only (a pre-existing
# constraint from the original 5-property design, not something this batch
# can add "F_FULL" or "F8" to without a schema change this round did not
# make). Since a mechanically-generated pair can mix two different
# families' transitions, tag each pair by its LAST (payload/tested) step's
# family -- a documented convention, not an attempt to hide the mixing
# (transition_1/transition_2 remain visible in every result row regardless).
_FAMILY_MAP = {
    "ROOT_ROTATE_VALID": "F1", "ROOT_ROTATE_SKIP": "F1", "ROOT_ROTATE_INSUF_THRESHOLD": "F1",
    "METADATA_BY_REMOVED_KEY": "F5",
    "TIMESTAMP_ADVANCE": "F3", "TIMESTAMP_REPLAY": "F3", "SNAPSHOT_ADVANCE": "F3", "SNAPSHOT_REPLAY": "F3",
    "DELEGATION_CREATE": "F4", "DELEGATION_REMOVE": "F4", "DELEGATED_REPLAY_AFTER_REMOVAL": "F4",
    "EXPIRE": "F3",
}

if __name__ == "__main__":  # guarded so this module can be imported without running the batch
    results = []
    corpus = []
    mismatches = []
    server = SimulatorServer(None)

    pairs = sorted(engine.enumerate_reachable_sequences(2)[2])
    print(f"Mechanically enumerated {len(pairs)} reachable ordered pairs from state_engine.py (full 12-transition alphabet).\n")

    for pair in pairs:
        # Predicted decisions, from the engine, BEFORE any execution (oracle and
        # execution kept independent -- the engine is never adjusted post hoc).
        predict_state = engine.INITIAL_STATE
        predicted = []
        for t in pair:
            predict_state, dec = engine.apply_transition(predict_state, t)
            predicted.append(dec.label)

        cid = pl.sequence_id("F_FULL", [f"PAIR-{'-'.join(pair)}"], list(pair))
        pair_family = _FAMILY_MAP[pair[-1]]
        corpus.append({
            "sequence_id": cid, "family": pair_family, "case_label": f"PAIR-{'-'.join(pair)}",
            "origin": "TSTM_GENERATED", "generation_method": "MECHANICAL_FULL_ALPHABET",
            "transitions": [{"step_index": i, "transition_type": t, "parameters": {}, "counts_toward_k": True}
                             for i, t in enumerate(pair)],
            "length": len(pair), "oracle_properties": [],
            "initial_state": {"R_v": 1, "R_K": ["root_key_0"], "R_t": 1, "T_v": 1, "S_v": 1, "G_v": 1,
                               "D": "DELEGATION_ABSENT", "E": "EXPIRATION_VALID"},
            "expected_state_trace": [], "boundary_states": [],
            "c2_pairs": [f"{pair[0]}->{pair[1]}"], "c3_triples": [],
        })

        for impl_name, entry in IMPLS.items():
            test_name = f"FULLPAIR_{'_'.join(pair)}_{impl_name}".replace(" ", "_")
            client = ClientRunner(entry, server, test_name)
            init_data, repo = server.new_test(test_name)
            construction_notes = []
            observed = []
            exec_status = "COMPLETED"
            try:
                assert client.init_client(init_data) == 0
                state = ExecState(repo)
                root_blocked_tracker = False
                for t in pair:
                    fn = EXECUTORS.get(t)
                    if fn is None:
                        exec_status = "INFEASIBLE"
                        construction_notes.append(f"no executor for {t}")
                        observed.append(None)
                        continue
                    rc = fn(repo, client, init_data, state, root_blocked_tracker)
                    observed.append("REJECT" if rc == 1 else "ACCEPT")
                    if rc == 1 and t in {"ROOT_ROTATE_SKIP", "ROOT_ROTATE_INSUF_THRESHOLD", "METADATA_BY_REMOVED_KEY"}:
                        root_blocked_tracker = True
                    if rc == 0 and t == "ROOT_ROTATE_VALID":
                        root_blocked_tracker = False
            except Exception as e:
                exec_status = "HARNESS_ERROR"
                construction_notes.append(f"EXCEPTION: {e}")

            match = (observed == predicted) if exec_status == "COMPLETED" else None
            row = {
                "sequence_id": cid, "implementation": impl_name, "family": pair_family,
                "transition_1": pair[0], "transition_2": pair[1],
                "engine_preconditions": "always-constructible (see state_engine.py rule comments)",
                "engine_expected_decisions": predicted,
                "observed_decisions": observed,
                "implementation_field": impl_name,
                "execution_status": exec_status,
                "match": match,
                "construction_notes": construction_notes,
                "raw_log_path": "scripts/run_full_pair_matrix.py stdout, this session",
            }
            results.append(row)
            if match is False:
                mismatches.append(row)
            print(f"[{pair[0]}, {pair[1]}] {impl_name}: predicted={predicted} observed={observed} "
                  f"status={exec_status} {'MATCH' if match else ('MISMATCH' if match is False else 'N/A')}")

    server.server_close()

    out_dir = os.path.join(REPO_DIR, "example_data")
    with open(os.path.join(out_dir, "MACOS_FULL_PAIR_MATRIX_corpus.json"), "w") as f:
        json.dump(corpus, f, indent=2)
    with open(os.path.join(out_dir, "MACOS_FULL_PAIR_MATRIX_results.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)

    total = len(results)
    print(f"\n\nDONE. {len(pairs)} pairs x {len(IMPLS)} implementations = {total} real executions.")
    print(f"Mismatches: {len(mismatches)}")
    for m in mismatches:
        print(" -", m["sequence_id"], m["implementation"], m["transition_1"], m["transition_2"],
              "predicted=", m["engine_expected_decisions"], "observed=", m["observed_decisions"])
