"""
Mechanical (hand-construction-free) generation and REAL execution of every
reachable ordered transition PAIR within the root-rotation sub-alphabet
{ROOT_ROTATE_VALID, ROOT_ROTATE_SKIP, ROOT_ROTATE_INSUF_THRESHOLD,
METADATA_BY_REMOVED_KEY}, enumerated directly by
tuf_study/analysis/state_engine.py -- not hand-picked.

This exists specifically to answer an external-review concern (PAPER_DRAFT.md Sec.11
item (1): all 7 sequences in the original pilot were hand-constructed, one
per property, even though the state engine (built earlier this round) makes
mechanical sampling from its own reachable-sequence set possible. This
script executes that mechanical sampling for real, against all three real
client implementations -- but is DELIBERATELY SCOPED to just the
root-rotation sub-alphabet (not the full 12-transition, 52-pair space),
because the executor functions below are only proven-correct for these four
transition types (reused verbatim from run_tstm_core.py's already-validated
p1_case/p1_control_case/p2_case/p4_case constructions). Building equally
well-tested executors for the timestamp/snapshot/delegation transitions
within this session's remaining time budget would have meant writing NEW,
unvalidated construction code under time pressure -- exactly the failure
mode the rest of this study's corrections were about avoiding. Extending
this to the full alphabet is Future Research, not attempted here.

Every pair below is REAL: real subprocess execution against real
python-tuf/go-tuf-v2/tuf-js binaries. Nothing is inferred or simulated at
the Python level beyond what RepositorySimulator itself does.
"""
import json
import os
import sys

EXPERIMENT_DIR = os.environ.get("TUF_STUDY_EXPERIMENT_DIR", r"C:\Users\yasemin.bozkurt\tuf_experiment")
REPO_DIR = os.environ.get("TUF_STUDY_REPO_DIR", r"C:\Users\yasemin.bozkurt\Desktop\new\tuf_study")
CONFORMANCE_DIR = os.path.join(EXPERIMENT_DIR, "tuf-conformance")

sys.path.insert(0, CONFORMANCE_DIR)
sys.path.insert(0, os.path.join(REPO_DIR, "analysis"))

from tuf.api.metadata import Root
from tuf.api.serialization.json import JSONSerializer
from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer

import tstm_analysis as pl
import state_engine as engine

PYTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "python-tuf", "run_python_tuf.bat")
GOTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "go-tuf", "go-tuf.exe")
TUFJS_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "tuf-js", "run_tuf_js.bat")
IMPLS = {"python-tuf": PYTUF_ENTRY, "go-tuf-v2": GOTUF_ENTRY, "tuf-js": TUFJS_ENTRY}

ROOT_FAMILY = {"ROOT_ROTATE_VALID", "ROOT_ROTATE_SKIP", "ROOT_ROTATE_INSUF_THRESHOLD", "METADATA_BY_REMOVED_KEY"}


def _manual_publish(repo, signers: list, replace_current: bool = False) -> None:
    """replace_current=True republishes the SAME version index instead of
    appending a new one -- required whenever the PRECEDING step in the
    sequence was a REJECT, because the client is still sequentially stuck
    trying to verify that not-yet-adopted version (TUF's root-update
    procedure, Sec.5.3.5, is strictly sequential -- it cannot skip ahead to
    a later version regardless of that later version's own validity). This
    is the exact same construction bug, generalized, that PAPER_DRAFT.md
    Sec.5 already reports finding while building the redesigned P1 case;
    finding it again here (independently, via mechanical pair enumeration
    rather than the hand-built P1 sequence) is itself additional evidence
    that this is a real, systematic property of the model -- not a
    one-off mistake in a single hand-written test."""
    md = repo.mds[Root.type]
    lst = repo.signed_mds.setdefault(Root.type, [])
    if replace_current and lst:
        # Must match the DECLARED version to the list position being
        # replaced, not just skip incrementing -- otherwise a
        # multiply-incremented leftover value (e.g. from a preceding SKIP,
        # which bumps version by 2 for one list append) survives into the
        # replacement and creates its own declared-version-vs-served-
        # position mismatch, independently REJECTable for a reason that has
        # nothing to do with what this call is actually trying to test.
        # Found via exactly this failure mode while mechanically executing
        # the (ROOT_ROTATE_SKIP, ROOT_ROTATE_VALID) pair -- see
        # See PAPER_DRAFT.md for the writeup.
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


class RootFamilyState:
    """Tracks exactly what each of the four executors below needs: the
    signer set the client currently trusts (satisfies the CURRENT root's
    threshold), the most recently superseded ("removed") signer set, and
    whether the immediately preceding step was a REJECT (which forces the
    next publish, if any, to replace rather than append -- see
    _manual_publish). On REJECT, current_signers/removed_signers do not
    change -- mirroring state_engine's own REJECT-leaves-state-unchanged
    rule; needs_replace does change (that IS the mechanism by which a
    REJECT's real-world consequence -- the client being stuck on a
    not-yet-adopted version -- gets carried forward)."""

    def __init__(self, repo):
        self.current_signers = dict(repo.signers[Root.type])
        self.removed_signers: dict | None = None
        self.needs_replace = False


def apply_root_transition(repo, client, init_data, state: RootFamilyState, transition_type: str) -> int:
    if transition_type == "ROOT_ROTATE_VALID":
        new_signer = repo.new_signer()
        repo.root.add_key(new_signer.public_key, Root.type)
        repo.root.roles[Root.type].keyids.clear()
        repo.root.add_key(new_signer.public_key, Root.type)
        _manual_publish(repo, list(state.current_signers.values()) + [new_signer],
                         replace_current=state.needs_replace)
        rc = client.refresh(init_data)
        if rc == 0:
            state.removed_signers = state.current_signers
            state.current_signers = {new_signer.public_key.keyid: new_signer}
            state.needs_replace = False
        else:
            state.needs_replace = True
        return rc

    if transition_type == "ROOT_ROTATE_SKIP":
        if not state.needs_replace:
            repo.root.version += 1
        repo.rotate_keys(Root.type)
        # NOTE: cannot use repo.publish() here when replace_current is needed --
        # RepositorySimulator.publish() unconditionally .append()s to
        # signed_mds[role] regardless of its verify_version flag (that flag
        # only skips its own version-number assertion, not the append-vs-
        # replace list operation), so it can never target an already-used
        # list index. Use the same manual, replace-aware publish as every
        # other transition here instead, signing with whatever
        # repo.rotate_keys() just set up as the new signer set.
        _manual_publish(repo, list(repo.signers[Root.type].values()), replace_current=state.needs_replace)
        rc = client.refresh(init_data)  # expected REJECT
        state.needs_replace = True  # still REJECT-outcome by definition; stays stuck
        return rc

    if transition_type == "ROOT_ROTATE_INSUF_THRESHOLD":
        new_signer = repo.new_signer()
        repo.root.roles[Root.type].keyids.clear()
        repo.root.add_key(new_signer.public_key, Root.type)
        _manual_publish(repo, [new_signer], replace_current=state.needs_replace)  # missing current_signers' signature
        rc = client.refresh(init_data)  # expected REJECT
        state.needs_replace = True
        return rc

    if transition_type == "METADATA_BY_REMOVED_KEY":
        assert state.removed_signers is not None, "precondition violated: no prior valid rotation"
        _manual_publish(repo, list(state.removed_signers.values()), replace_current=state.needs_replace)
        rc = client.refresh(init_data)  # expected REJECT
        state.needs_replace = True
        return rc

    raise ValueError(f"no root-family executor for {transition_type}")


def run_pair(family: str, transitions: tuple[str, str], server, results, corpus):
    cid = pl.sequence_id(family, [f"MECH-{'-'.join(transitions)}"], list(transitions))
    corpus.append({
        "sequence_id": cid, "family": family, "case_label": f"MECH-{'-'.join(transitions)}",
        "origin": "TSTM_GENERATED", "generation_method": "MECHANICAL",
        "transitions": [{"step_index": i, "transition_type": t, "parameters": {}, "counts_toward_k": True}
                         for i, t in enumerate(transitions)],
        "length": len(transitions), "oracle_properties": [],
        "initial_state": {"R_v": 1, "R_K": ["root_key_0"], "R_t": 1, "T_v": 1, "S_v": 1, "G_v": 1,
                           "D": "DELEGATION_ABSENT", "E": "EXPIRATION_VALID"},
        "expected_state_trace": [], "boundary_states": [],
        "c2_pairs": [f"{transitions[0]}->{transitions[1]}"], "c3_triples": [],
    })
    state_check = engine.INITIAL_STATE
    predicted = []
    for t in transitions:
        result = engine.apply_transition(state_check, t)
        state_check, decision = result
        predicted.append(decision.label)

    for impl_name, entry in IMPLS.items():
        test_name = f"MECH_{family}_{'_'.join(transitions)}_{impl_name}".replace(" ", "_")
        client = ClientRunner(entry, server, test_name)
        init_data, repo = server.new_test(test_name)
        assert client.init_client(init_data) == 0
        state = RootFamilyState(repo)
        observed = []
        for t in transitions:
            rc = apply_root_transition(repo, client, init_data, state, t)
            observed.append("REJECT" if rc == 1 else "ACCEPT")
        results.append({
            "sequence_id": cid, "implementation": impl_name, "family": family,
            "transitions": list(transitions), "predicted_decisions": predicted,
            "observed_decisions": observed, "match": predicted == observed,
        })
        print(f"[MECH {transitions}] {impl_name}: predicted={predicted} observed={observed} "
              f"{'MATCH' if predicted == observed else 'MISMATCH'}")


def main():
    server = SimulatorServer(None)
    corpus, results = [], []
    seqs = engine.enumerate_reachable_sequences(2)
    pairs = sorted(s for s in seqs[2] if s[0] in ROOT_FAMILY and s[1] in ROOT_FAMILY)
    print(f"Mechanically enumerated {len(pairs)} reachable root-family pairs from state_engine.py:")
    for p in pairs:
        print(" ", p)
    print()
    for pair in pairs:
        run_pair("F1", pair, server, results, corpus)
    server.server_close()

    out_dir = os.path.join(REPO_DIR, "example_data")
    with open(os.path.join(out_dir, "MECHANICAL_root_family_pairs_corpus.json"), "w") as f:
        json.dump(corpus, f, indent=2)
    with open(os.path.join(out_dir, "MECHANICAL_root_family_pairs_results.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)

    total = len(results)
    mismatches = [r for r in results if not r["match"]]
    print(f"\n\nDONE. {total} real (sequence, implementation) executions across "
          f"{len(pairs)} mechanically-enumerated pairs x {len(IMPLS)} implementations.")
    print(f"Mismatches between engine prediction and real observed behavior: {len(mismatches)}")
    for m in mismatches:
        print(" -", m)


if __name__ == "__main__":
    main()
