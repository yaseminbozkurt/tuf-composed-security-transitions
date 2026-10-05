"""
Full reachable ordered-TRIPLE (K=3) mechanical execution -- all 266
core-family-restricted triples state_engine.py enumerates at depth 3.
Executed only after the full 52-pair batch (run_full_pair_matrix.py)
succeeded completely (156/156, 0 mismatches), per explicit priority
ordering: pairs first, triples only if pair executors proved stable.

Reuses the EXACT SAME per-transition executor functions the pair matrix
used (imported, not re-implemented) -- see TRIPLES_FEASIBILITY.md for why
this required zero new, unvalidated construction code: the executors are
generic in sequence length by design.
"""
import json
import os
import sys

EXPERIMENT_DIR = os.environ.get("TUF_STUDY_EXPERIMENT_DIR", r"C:\Users\yasemin.bozkurt\tuf_experiment")
REPO_DIR = os.environ.get("TUF_STUDY_REPO_DIR", r"C:\Users\yasemin.bozkurt\Desktop\new\tuf_study")
CONFORMANCE_DIR = os.path.join(EXPERIMENT_DIR, "tuf-conformance")

sys.path.insert(0, CONFORMANCE_DIR)
sys.path.insert(0, os.path.join(REPO_DIR, "analysis"))
sys.path.insert(0, EXPERIMENT_DIR)

from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer

import tstm_analysis as pl
import state_engine as engine
from run_full_pair_matrix import EXECUTORS, ExecState, _FAMILY_MAP, PYTUF_ENTRY, GOTUF_ENTRY, TUFJS_ENTRY

IMPLS = {"python-tuf": PYTUF_ENTRY, "go-tuf-v2": GOTUF_ENTRY, "tuf-js": TUFJS_ENTRY}

CORE_RELEVANT = {
    "ROOT_ROTATE_VALID", "ROOT_ROTATE_SKIP", "ROOT_ROTATE_INSUF_THRESHOLD",
    "TIMESTAMP_ADVANCE", "TIMESTAMP_REPLAY", "SNAPSHOT_ADVANCE", "SNAPSHOT_REPLAY",
    "DELEGATION_CREATE", "DELEGATION_REMOVE", "DELEGATED_REPLAY_AFTER_REMOVAL",
    "METADATA_BY_REMOVED_KEY",
}

results = []
corpus = []
mismatches = []
server = SimulatorServer(None)

triples = sorted(t for t in engine.enumerate_reachable_sequences(3)[3]
                  if all(x in CORE_RELEVANT for x in t))
print(f"Mechanically enumerated {len(triples)} core-family-restricted reachable triples.\n")

for idx, triple in enumerate(triples):
    predict_state = engine.INITIAL_STATE
    predicted = []
    for t in triple:
        predict_state, dec = engine.apply_transition(predict_state, t)
        predicted.append(dec.label)

    cid = pl.sequence_id("F_FULL3", [f"TRIPLE-{'-'.join(triple)}"], list(triple))
    triple_family = _FAMILY_MAP[triple[-1]]
    corpus.append({
        "sequence_id": cid, "family": triple_family, "case_label": f"TRIPLE-{'-'.join(triple)}",
        "origin": "TSTM_GENERATED", "generation_method": "MECHANICAL_FULL_ALPHABET_K3",
        "transitions": [{"step_index": i, "transition_type": t, "parameters": {}, "counts_toward_k": True}
                         for i, t in enumerate(triple)],
        "length": len(triple), "oracle_properties": [],
        "initial_state": {"R_v": 1, "R_K": ["root_key_0"], "R_t": 1, "T_v": 1, "S_v": 1, "G_v": 1,
                           "D": "DELEGATION_ABSENT", "E": "EXPIRATION_VALID"},
        "expected_state_trace": [], "boundary_states": [],
        "c2_pairs": [f"{triple[0]}->{triple[1]}", f"{triple[1]}->{triple[2]}"],
        "c3_triples": [f"{triple[0]}->{triple[1]}->{triple[2]}"],
    })

    for impl_name, entry in IMPLS.items():
        test_name = f"TRIPLE_{idx}_{impl_name}".replace(" ", "_")
        client = ClientRunner(entry, server, test_name)
        init_data, repo = server.new_test(test_name)
        construction_notes = []
        observed = []
        exec_status = "COMPLETED"
        try:
            assert client.init_client(init_data) == 0
            state = ExecState(repo)
            root_blocked_tracker = False
            for t in triple:
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
            "sequence_id": cid, "implementation": impl_name, "family": triple_family,
            "transition_1": triple[0], "transition_2": triple[1], "transition_3": triple[2],
            "engine_expected_decisions": predicted,
            "observed_decisions": observed,
            "execution_status": exec_status,
            "match": match,
            "construction_notes": construction_notes,
            "raw_log_path": "scripts/run_triple_matrix.py stdout, this session",
        }
        results.append(row)
        if match is False:
            mismatches.append(row)

    if (idx + 1) % 20 == 0 or (idx + 1) == len(triples):
        print(f"...{idx + 1}/{len(triples)} triples done, {len(mismatches)} mismatches so far")

server.server_close()

out_dir = os.path.join(REPO_DIR, "example_data")
with open(os.path.join(out_dir, "TRIPLE_MATRIX_corpus.json"), "w") as f:
    json.dump(corpus, f, indent=2)
with open(os.path.join(out_dir, "TRIPLE_MATRIX_results.json"), "w") as f:
    json.dump(results, f, indent=2, default=str)

total = len(results)
print(f"\n\nDONE. {len(triples)} triples x {len(IMPLS)} implementations = {total} real executions.")
print(f"Mismatches: {len(mismatches)}")
for m in mismatches:
    print(" -", m["sequence_id"], m["implementation"], m["transition_1"], m["transition_2"], m["transition_3"],
          "predicted=", m["engine_expected_decisions"], "observed=", m["observed_decisions"])
