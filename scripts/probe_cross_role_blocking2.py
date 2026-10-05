"""Further probes: does a rejected TIMESTAMP_REPLAY block subsequent
DELEGATION_CREATE / ROOT_ROTATE_VALID? Does a rejected SNAPSHOT_REPLAY block
subsequent DELEGATION_CREATE? Needed to correctly generalize the
root_blocked finding from probe_cross_role_blocking.py to the other roles
before building the full 52-pair executor."""
import os
import sys

CONFORMANCE_DIR = r"C:\Users\yasemin.bozkurt\tuf_experiment\tuf-conformance"
sys.path.insert(0, CONFORMANCE_DIR)

from tuf.api.metadata import Root, Snapshot, Timestamp, Targets, DelegatedRole
from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer

PYTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "python-tuf", "run_python_tuf.bat")
GOTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "go-tuf", "go-tuf.exe")
IMPLS = {"python-tuf": PYTUF_ENTRY, "go-tuf-v2": GOTUF_ENTRY}

server = SimulatorServer(None)


def probe(name, fn):
    for impl_name, entry in IMPLS.items():
        test_name = f"{name}_{impl_name}"
        client = ClientRunner(entry, server, test_name)
        init_data, repo = server.new_test(test_name)
        assert client.init_client(init_data) == 0
        results = fn(repo, client, init_data)
        print(f"{name} / {impl_name}: {results}")


def timestamp_replay_then_delegation_create(repo, client, init_data):
    r0 = client.refresh(init_data)
    repo.publish([Timestamp.type])
    r1 = client.refresh(init_data)  # ACCEPT expected (advance)
    del repo.signed_mds[Timestamp.type]
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])
    r2 = client.refresh(init_data)  # REJECT expected (replay)
    # now attempt an ordinary delegation create
    role = DelegatedRole("delegated", [], 1, False, ["delegatedpath/*"])
    delegated_targets = Targets(expires=repo.safe_expiry)
    repo.add_delegation(Targets.type, role, delegated_targets)
    repo.publish(["delegated", Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])
    r3 = client.refresh(init_data)
    return {"baseline": r0, "ts_advance": r1, "ts_replay(REJECT_expected)": r2, "delegation_create_after": r3}


def timestamp_replay_then_root_valid(repo, client, init_data):
    r0 = client.refresh(init_data)
    repo.publish([Timestamp.type])
    r1 = client.refresh(init_data)
    del repo.signed_mds[Timestamp.type]
    repo.timestamp.version = 1
    repo.publish([Timestamp.type])
    r2 = client.refresh(init_data)  # REJECT expected
    # now attempt an ordinary valid root rotation
    old_signers = dict(repo.signers[Root.type])
    new_signer = repo.new_signer()
    repo.root.add_key(new_signer.public_key, Root.type)
    repo.root.roles[Root.type].keyids.clear()
    repo.root.add_key(new_signer.public_key, Root.type)
    repo.signers[Root.type] = {new_signer.public_key.keyid: new_signer}
    from tuf.api.serialization.json import JSONSerializer
    md = repo.mds[Root.type]
    md.signed.version += 1
    md.signatures.clear()
    for s in list(old_signers.values()) + [new_signer]:
        md.sign(s, append=True)
    repo.signed_mds.setdefault(Root.type, []).append(md.to_bytes(JSONSerializer()))
    r3 = client.refresh(init_data)
    return {"baseline": r0, "ts_advance": r1, "ts_replay(REJECT_expected)": r2, "root_valid_after": r3}


probe("TSREPLAY_then_DELEGATION", timestamp_replay_then_delegation_create)
probe("TSREPLAY_then_ROOTVALID", timestamp_replay_then_root_valid)

server.server_close()
