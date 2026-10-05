"""Abstraction-adequacy probe -- referee analysis A2 / concern M3.

The engine collapses many parameterizations of a transition class onto a
single symbol (e.g. the official `root_rotation_cases` dict distinguishes
15 named root-rotation scenarios; the engine has just ROOT_ROTATE_VALID and
ROOT_ROTATE_INSUF_THRESHOLD). This probe tests whether that collapse is
*decision-invariant*: does every parameterization the engine maps to
ROOT_ROTATE_VALID actually yield ACCEPT on all three real clients, and
every one it maps to ROOT_ROTATE_INSUF_THRESHOLD actually yield REJECT?

Construction is byte-for-byte the official
tuf_conformance/test_updater_key_rotations.py::test_root_rotation logic,
re-parametrized here over a subset of its own case dictionary. Every
decision is a real subprocess run via ClientRunner. Run on macOS/arm64.
"""
import os
import sys
from dataclasses import dataclass

CONF = os.environ.get("TUF_STUDY_EXPERIMENT_DIR",
                      os.path.expanduser("~/tuf_experiment_macos")) + "/tuf-conformance"
sys.path.insert(0, CONF)
from tuf.api.metadata import Root, Snapshot, Targets, Timestamp  # noqa: E402
from tuf_conformance._internal.client_runner import ClientRunner  # noqa: E402
from tuf_conformance._internal.simulator_server import SimulatorServer  # noqa: E402

PYTUF = CONF + "/clients/python-tuf/python_tuf.py"
GOTUF = CONF + "/clients/go-tuf/go-tuf"
TUFJS = os.path.dirname(CONF) + "/tuf-js/tuf-conformance-entrypoint.js"
IMPLS = {"python-tuf": PYTUF, "go-tuf-v2": GOTUF, "tuf-js": TUFJS}


@dataclass
class MdVersion:
    keys: list
    threshold: int
    sigs: list
    res: bool = True


# Subset of the official root_rotation_cases -- distinct parameterizations
# (key counts, threshold changes, multi-step chains) that the engine
# collapses onto ONE of two symbols.
VALID_VARIANTS = {  # -> engine symbol ROOT_ROTATE_VALID, expect ACCEPT
    "1-of-1-key-rotation": [MdVersion([1], 1, [1]), MdVersion([2], 1, [2, 1]), MdVersion([2], 1, [2])],
    "3-of-5-different-keycombos": [MdVersion([0,1,2,3,4],3,[0,2,4]), MdVersion([0,1,2,3,4],3,[0,4,1]),
                                    MdVersion([0,1,2,3,4],3,[0,1,3]), MdVersion([0,1,2,3,4],3,[0,1,3])],
    "3-of-5-one-key-rotated": [MdVersion([0,1,2,3,4],3,[0,2,4]), MdVersion([0,1,3,4,5],3,[0,4,1])],
    "1-of-3-threshold-increase-to-2-of-3": [MdVersion([1,2,3],1,[1]), MdVersion([1,2,3],2,[1,2])],
    "2-of-3-threshold-decrease-to-1-of-3": [MdVersion([1,2,3],2,[1,2]), MdVersion([1,2,3],1,[1,2]),
                                             MdVersion([1,2,3],1,[1])],
    "1-of-2-threshold-increase-to-2-of-2": [MdVersion([1],1,[1]), MdVersion([1,2],2,[1,2])],
}
INSUF_VARIANTS = {  # -> engine symbol ROOT_ROTATE_INSUF_THRESHOLD, expect REJECT
    "fail-not-signed-with-old-key": [MdVersion([1],1,[1]), MdVersion([2],1,[2,3,4], res=False)],
    "fail-not-signed-with-new-key": [MdVersion([1],1,[1]), MdVersion([2],1,[1,3,4], res=False)],
    "3-of-5-fails-not-signed-3-new": [MdVersion([0,1,2,3,4],3,[0,2,4]), MdVersion([0,1,3,4,5],3,[0,2,4], res=False)],
    "threshold-bump-new-not-reached": [MdVersion([1,2,3],1,[1]), MdVersion([1,2,3],2,[2], res=False)],
    "threshold-decr-old-not-reached": [MdVersion([1,2,3],2,[1,2]), MdVersion([1,2,3],1,[1], res=False)],
}


def run_variant(entry, versions):
    srv = SimulatorServer("inv")
    init_data, repo = srv.new_test("inv")
    del repo.signed_mds[Root.type]
    signers = [repo.new_signer() for _ in range(10)]
    for rv in versions:
        repo.root.roles[Root.type].keyids.clear()
        repo.signers[Root.type].clear()
        repo.root.roles[Root.type].threshold = rv.threshold
        for i in rv.keys:
            repo.root.add_key(signers[i].public_key, Root.type)
        for i in rv.sigs:
            repo.add_signer(Root.type, signers[i])
        repo.publish([Root.type])
    repo.publish([Targets.type, Snapshot.type, Timestamp.type])
    init_data.trusted_root = repo.fetch_metadata("root", 1)
    c = ClientRunner(entry, srv, "inv")
    assert c.init_client(init_data) == 0
    return c.refresh(init_data)   # 0 = ACCEPT, 1 = REJECT


def check(group_name, variants, engine_symbol, expect_rc):
    print(f"\n=== {group_name}  -> engine symbol {engine_symbol}  "
          f"(engine predicts rc={expect_rc}) ===")
    all_ok = True
    for vname, versions in variants.items():
        row = []
        for impl, entry in IMPLS.items():
            rc = run_variant(entry, versions)
            row.append(f"{impl}={rc}")
            if rc != expect_rc:
                all_ok = False
        status = "OK" if all(f.endswith(f"={expect_rc}") for f in row) else "*** DEVIATION ***"
        print(f"  [{vname:38}] {'  '.join(row)}   {status}")
    return all_ok


ok1 = check("6 distinct ROOT_ROTATE_VALID parameterizations", VALID_VARIANTS,
            "ROOT_ROTATE_VALID", 0)
ok2 = check("5 distinct ROOT_ROTATE_INSUF_THRESHOLD parameterizations", INSUF_VARIANTS,
            "ROOT_ROTATE_INSUF_THRESHOLD", 1)

print("\n" + "=" * 64)
print("ABSTRACTION DECISION-INVARIANCE:",
      "HOLDS -- every parameterization matches its engine symbol's decision "
      "on all 3 implementations" if (ok1 and ok2) else
      "VIOLATED -- see *** DEVIATION *** rows above")
