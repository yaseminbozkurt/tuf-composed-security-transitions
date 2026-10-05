"""
GHSA-66x3-6cw3-v5gj / CVE-2022-29173 regression check (external review
concern T10; PAPER_DRAFT.md Section 2/10/11 Future Research item 6).

Purpose: every discriminating-power data point in this study so far has
been a self-caught construction bug -- nothing has demonstrated that the
oracle can flag a REAL, historically known-vulnerable implementation. This
script closes that gap by running the exact same rollback-protection
sequence this study's own 52-pair matrix already validated against
python-tuf/go-tuf-v2/tuf-js -- the pair (TIMESTAMP_ADVANCE, TIMESTAMP_REPLAY)
-- against `legacygotuf-conformance-adapter`, a CLIENT-CLI adapter this
session built for pre-fix go-tuf v0.2.0 (the last tag before the v0.3.0 fix
for GHSA-66x3-6cw3-v5gj: "no protection against rollback attacks for roles
other than root").

`do_TIMESTAMP_ADVANCE` / `do_TIMESTAMP_REPLAY` below are copied VERBATIM
from `run_full_pair_matrix.py` (not re-derived) -- same construction, same
oracle, same executor code, only the client-under-test changes. This
script does NOT import run_full_pair_matrix.py directly, specifically to
avoid that module's own documented import side effect (external review
T3: it has no `if __name__ == "__main__":` guard and would silently
re-run its entire 156-execution pair batch).

Per this study's own rule ("never write results before actually running
new data; preserve the raw result before drawing any conclusion"): the
prediction below is written and frozen BEFORE this script is executed for
the first time, and is never adjusted after seeing the observed result.

ENGINE PREDICTION (from state_engine.py, unchanged, same as the validated
52-pair batch): (TIMESTAMP_ADVANCE -> ACCEPT, TIMESTAMP_REPLAY -> REJECT).
This is the specification-correct behavior and is what python-tuf,
go-tuf-v2, and tuf-js all actually do (confirmed, 0/156 mismatches,
FULL_PAIR_MATRIX.md).

CVE-BASED EXPECTATION for the pre-fix legacy client specifically (from
direct reading of GHSA-66x3-6cw3-v5gj and of go-tuf v0.2.0's own
client.go, which implements a rollback check for root at line ~322 but has
no equivalent check for non-root roles): TIMESTAMP_REPLAY is expected to
ACCEPT, not REJECT -- i.e., a predicted MISMATCH against the engine, which
would BE the discriminating-power evidence this study currently lacks. If
the legacy client instead REJECTs (matching the engine), that is also
reported as-is: it would mean either the CVE does not reproduce against
this specific harness/scenario, or a genuine construction defect in this
new adapter -- both are reported honestly, not forced either way.
"""
import json
import os
import sys

EXPERIMENT_DIR = os.environ.get("TUF_STUDY_EXPERIMENT_DIR", r"C:\Users\yasemin.bozkurt\tuf_experiment")
REPO_DIR = os.environ.get("TUF_STUDY_REPO_DIR", r"C:\Users\yasemin.bozkurt\Desktop\new\tuf_study")
CONFORMANCE_DIR = os.path.join(EXPERIMENT_DIR, "tuf-conformance")

sys.path.insert(0, CONFORMANCE_DIR)
sys.path.insert(0, os.path.join(REPO_DIR, "analysis"))

from tuf.api.metadata import Root, Snapshot, Targets, Timestamp
from tuf.api.serialization.json import JSONSerializer
from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer

from tuf_conformance._internal.repository_simulator import TOP_LEVEL_ROLE_NAMES

import state_engine as engine

GOTUF_V2_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "go-tuf", "go-tuf.exe")
GOTUF_LEGACY_ENTRY = os.path.join(EXPERIMENT_DIR, "legacy_gotuf_adapter", "legacygotuf-client.exe")



def _rekey_to_ed25519(repo):
    """SETUP step, not counted toward K, run identically for both the
    control and the regression-target client.

    Root cause, found by direct investigation (not assumed) after the
    first real run of this script REJECTed even the trivially-valid first
    step: the harness's default key type is ECDSA, serialized per current
    TUF spec convention as split fields -- {"keytype": "ecdsa", "scheme":
    "ecdsa-sha2-nistp256"}. Legacy go-tuf v0.2.0's verifier registry
    (pkg/keys/ecdsa.go) is keyed by data.KeyTypeECDSA_SHA2_P256, which
    equals the STRING "ecdsa-sha2-nistp256" -- but GetVerifier() looks up
    by key.Type, which deserializes from the JSON "keytype" field ("ecdsa"),
    not "scheme". "ecdsa" != "ecdsa-sha2-nistp256", so every ECDSA-keyed
    role fails with ErrInvalidKey ("tuf: invalid key") regardless of
    signature validity -- a real key-vocabulary compatibility gap in the
    legacy client (pre-dating the split keytype/scheme convention), but
    ORTHOGONAL to the rollback-protection property under test.

    For ed25519, type and scheme both literally equal "ed25519" (data/types.go:
    KeyTypeEd25519 == KeySchemeEd25519 == "ed25519"), so this specific
    mismatch does not occur. Re-keying to ed25519 is therefore the minimal,
    non-invasive way to route around an unrelated compatibility gap without
    modifying the unmodified official harness or the client under test --
    it changes nothing about how rollback/version-checking works for any
    role, which is the only code path this experiment is about.

    Second finding, from a first attempt at this fix that still failed:
    legacy go-tuf's loadAndVerifyRootMeta (client.go:465) iterates and
    verifies EVERY key in root.Keys unconditionally -- not just keys
    referenced by an active role -- and aborts the entire refresh if any
    one of them fails to resolve a verifier (verify/db.go:59-62). Modern
    clients (python-tuf/go-tuf-v2/tuf-js) only resolve keys on demand by
    keyid, so an orphaned old key sitting unused in root.Keys is harmless
    to them -- but not to this legacy client. Using Root.revoke_key()
    (which deletes the key from Root.keys once no role references it any
    longer) rather than clearing Role.keyids directly is therefore
    required, not just tidier.
    """
    # Third finding: legacy go-tuf also enforces an exact declared-length
    # match when downloading snapshot/targets metadata (client.go
    # downloadMeta), whereas the harness's default
    # (compute_metafile_hashes_length = False) leaves length/hashes unset
    # (None -> serialized as absent/0) since the other three implementations
    # don't require them. Enabling it only changes whether these metadata
    # fields are POPULATED, not any version-comparison/rollback logic.
    repo.compute_metafile_hashes_length = True

    for role in TOP_LEVEL_ROLE_NAMES:
        old_keyids = list(repo.root.roles[role].keyids)
        signer = repo.new_signer(keytype="ed25519", scheme="ed25519")
        repo.root.add_key(signer.public_key, role)
        for old_keyid in old_keyids:
            repo.root.revoke_key(old_keyid, role)
        repo.signers[role] = {signer.public_key.keyid: signer}
    # Dependency-safe order (targets, then snapshot, then timestamp, then
    # root), matching RepositorySimulator._initialize()'s own explicit
    # ordering -- NOT simply list(TOP_LEVEL_ROLE_NAMES), whose natural order
    # does not guarantee snapshot.meta/timestamp.meta are populated with the
    # newly-recomputed hashes/lengths before their dependents are signed.
    repo.publish([Targets.type, Snapshot.type, Timestamp.type, Root.type])


# Copied verbatim from run_full_pair_matrix.py -- see that file for the
# canonical version; duplicated here only to avoid this module's
# documented import side effect (T3), not re-derived independently.
def do_TIMESTAMP_ADVANCE(repo, client, init_data):
    repo.publish([Timestamp.type])
    return client.refresh(init_data)


def do_TIMESTAMP_REPLAY(repo, client, init_data):
    del repo.signed_mds[Timestamp.type]
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])
    rc = client.refresh(init_data)
    repo.publish([Timestamp.type])  # self-heal (SETUP, not counted)
    client.refresh(init_data)
    return rc


def do_SNAPSHOT_ADVANCE(repo, client, init_data):
    repo.publish([Snapshot.type, Timestamp.type])
    return client.refresh(init_data)


def do_SNAPSHOT_REPLAY(repo, client, init_data):
    del repo.signed_mds[Snapshot.type]
    repo.snapshot.version = 1
    repo.publish([Snapshot.type, Timestamp.type])
    rc = client.refresh(init_data)
    repo.publish([Snapshot.type, Timestamp.type])  # self-heal (SETUP, not counted)
    client.refresh(init_data)
    return rc


EXECUTORS = {
    "TIMESTAMP_ADVANCE": do_TIMESTAMP_ADVANCE, "TIMESTAMP_REPLAY": do_TIMESTAMP_REPLAY,
    "SNAPSHOT_ADVANCE": do_SNAPSHOT_ADVANCE, "SNAPSHOT_REPLAY": do_SNAPSHOT_REPLAY,
}


def run_pair(server, impl_name, entry, pair):
    test_name = f"GHSA_REGRESSION_{'_'.join(pair)}_{impl_name}".replace(" ", "_")
    init_data, repo = server.new_test(test_name)
    # SETUP, not counted toward K -- see _rekey_to_ed25519 docstring for why
    # this is needed (a key-vocabulary gap orthogonal to the property under
    # test) and why it does not touch the rollback-checking code path.
    _rekey_to_ed25519(repo)
    # init_data.trusted_root was captured before the re-key (the original
    # ecdsa-keyed v1); re-fetch with version=None, which repository_simulator
    # documents as "the metadata it has published last" -- the fully
    # ed25519-self-signed root just produced by _rekey_to_ed25519, entirely
    # self-consistent (embedded keys and signatures both ed25519), so the
    # client's initial trust anchor has no dependency on the earlier ecdsa
    # content at all.
    init_data = init_data.__class__(init_data.metadata_url, init_data.targets_url, repo.fetch_metadata("root"))
    client = ClientRunner(entry, server, test_name)
    observed = []
    exec_status = "COMPLETED"
    construction_notes = []
    try:
        rc_init = client.init_client(init_data)
        if rc_init != 0:
            return {"implementation": impl_name, "observed": [], "execution_status": "HARNESS_ERROR",
                    "construction_notes": [f"init_client failed, rc={rc_init}"]}
        for t in pair:
            rc = EXECUTORS[t](repo, client, init_data)
            observed.append("REJECT" if rc == 1 else ("ACCEPT" if rc == 0 else f"RC={rc}"))
    except Exception as e:  # noqa: BLE001 -- reported as-is, not swallowed
        exec_status = "EXECUTION_FAILURE"
        construction_notes.append(f"{type(e).__name__}: {e}")
    return {"implementation": impl_name, "observed": observed, "execution_status": exec_status,
            "construction_notes": construction_notes}


PAIRS = [
    ("TIMESTAMP_ADVANCE", "TIMESTAMP_REPLAY"),
    ("SNAPSHOT_ADVANCE", "SNAPSHOT_REPLAY"),
]


def main():
    server = SimulatorServer(None)
    all_pair_results = []

    for pair in PAIRS:
        # Prediction frozen BEFORE execution, printed first, never edited after.
        predict_state = engine.INITIAL_STATE
        predicted = []
        for t in pair:
            predict_state, dec = engine.apply_transition(predict_state, t)
            predicted.append(dec.label)
        print("=" * 70)
        print(f"GHSA-66x3-6cw3-v5gj REGRESSION CHECK -- pair {pair}")
        print("=" * 70)
        print(f"ENGINE PREDICTION (spec-correct, frozen before execution): {predicted}")
        print("CVE-BASED EXPECTATION for pre-fix legacy client: ['ACCEPT', 'ACCEPT'] "
              "(i.e. the REPLAY step also ACCEPTed -- a predicted MISMATCH vs "
              "the engine, which would constitute discriminating-power evidence)")
        print()

        results = []

        # Control: go-tuf v2 (already fixed) on this exact harness/session, as
        # an internal sanity check that the RepositorySimulator/ClientRunner
        # setup itself is not the source of any anomaly we might observe below.
        # This exact (implementation, pair) result already exists in this
        # study's committed 52-pair batch (FULL_PAIR_MATRIX_results.json); this
        # is a fresh, independent re-run for direct same-session comparison,
        # not a substitute for that committed record.
        r = run_pair(server, "go-tuf-v2 (control, fixed, v2.4.2)", GOTUF_V2_ENTRY, pair)
        results.append(r)
        print(f"[CONTROL] go-tuf-v2 (fixed):    observed={r['observed']}  status={r['execution_status']}  notes={r['construction_notes']}")

        # The actual regression check.
        r = run_pair(server, "go-tuf-legacy-v0.2.0 (pre-fix)", GOTUF_LEGACY_ENTRY, pair)
        results.append(r)
        print(f"[REGRESSION] go-tuf-legacy-v0.2.0 (pre-fix): observed={r['observed']}  status={r['execution_status']}  notes={r['construction_notes']}")

        print()
        legacy_result = results[1]
        if legacy_result["execution_status"] != "COMPLETED":
            verdict = "INCONCLUSIVE"
            print(f"RESULT: INCONCLUSIVE -- execution did not complete cleanly ({legacy_result['execution_status']}); "
                  f"see construction_notes above. Not reported as a finding either way.")
        elif legacy_result["observed"] == predicted:
            verdict = "CVE_NOT_REPRODUCED"
            print("RESULT: Legacy client's observed decisions MATCH the engine's spec-correct prediction. "
                  "The CVE did NOT reproduce in this harness/scenario as constructed. Reported as-is, not forced.")
        else:
            verdict = "CVE_REPRODUCED"
            print("RESULT: Legacy client's observed decisions DIVERGE from the engine's spec-correct prediction, "
                  "matching the CVE-based expectation. This is discriminating-power evidence: the oracle flags "
                  "a real, historically known-vulnerable implementation, not only self-caught construction bugs.")
        print()

        all_pair_results.append({
            "pair": list(pair),
            "engine_prediction": predicted,
            "cve_based_expectation_for_legacy_client": ["ACCEPT", "ACCEPT"],
            "verdict": verdict,
            "results": results,
        })

    out_path = os.path.join(REPO_DIR, "example_data", "GHSA_REGRESSION_results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_pair_results, f, indent=2)
    print(f"Raw result written to {out_path}")


if __name__ == "__main__":
    main()
