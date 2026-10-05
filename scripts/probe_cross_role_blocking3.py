"""Third probe round: does EXPIRE (timestamp-targeted) or SNAPSHOT_REPLAY
leave dangling contamination for a following, unrelated transition, the way
TIMESTAMP_REPLAY->ROOT_VALID did but TIMESTAMP_REPLAY->DELEGATION_CREATE
did not? Testing both directions needed before finalizing state_engine's
per-role blocking model."""
import os
import sys

CONFORMANCE_DIR = r"C:\Users\yasemin.bozkurt\tuf_experiment\tuf-conformance"
sys.path.insert(0, CONFORMANCE_DIR)

from tuf.api.metadata import Root, Snapshot, Timestamp, Targets, DelegatedRole
from tuf_conformance._internal import utils
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
        print(f"{name} / {impl_name}: {fn(repo, client, init_data)}")


def expire_then_root_valid(repo, client, init_data):
    r0 = client.refresh(init_data)
    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.publish([Timestamp.type])
    r1 = client.refresh(init_data)  # REJECT expected (expired)
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
    r2 = client.refresh(init_data)
    return {"baseline": r0, "ts_expire(REJECT_exp)": r1, "root_valid_after": r2}


def expire_then_delegation_create(repo, client, init_data):
    r0 = client.refresh(init_data)
    repo.timestamp.expires = utils.get_date_n_days_in_past(5)
    repo.publish([Timestamp.type])
    r1 = client.refresh(init_data)
    role = DelegatedRole("delegated", [], 1, False, ["delegatedpath/*"])
    delegated_targets = Targets(expires=repo.safe_expiry)
    repo.add_delegation(Targets.type, role, delegated_targets)
    repo.publish(["delegated", Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])
    r2 = client.refresh(init_data)
    return {"baseline": r0, "ts_expire(REJECT_exp)": r1, "delegation_create_after": r2}


def snapshot_replay_then_delegation_create(repo, client, init_data):
    r0 = client.refresh(init_data)
    repo.publish([Snapshot.type, Timestamp.type])
    r1 = client.refresh(init_data)
    del repo.signed_mds[Snapshot.type]
    repo.snapshot.version = 1
    repo.publish([Snapshot.type, Timestamp.type])
    r2 = client.refresh(init_data)  # REJECT expected
    role = DelegatedRole("delegated", [], 1, False, ["delegatedpath/*"])
    delegated_targets = Targets(expires=repo.safe_expiry)
    repo.add_delegation(Targets.type, role, delegated_targets)
    repo.publish(["delegated", Targets.type])
    repo.publish([Snapshot.type, Timestamp.type])
    r3 = client.refresh(init_data)
    return {"baseline": r0, "snap_advance": r1, "snap_replay(REJECT_exp)": r2, "delegation_create_after": r3}


def snapshot_replay_then_root_valid(repo, client, init_data):
    r0 = client.refresh(init_data)
    repo.publish([Snapshot.type, Timestamp.type])
    r1 = client.refresh(init_data)
    del repo.signed_mds[Snapshot.type]
    repo.snapshot.version = 1
    repo.publish([Snapshot.type, Timestamp.type])
    r2 = client.refresh(init_data)
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
    return {"baseline": r0, "snap_advance": r1, "snap_replay(REJECT_exp)": r2, "root_valid_after": r3}


probe("EXPIRE_then_ROOTVALID", expire_then_root_valid)
probe("EXPIRE_then_DELEGATION", expire_then_delegation_create)
probe("SNAPREPLAY_then_DELEGATION", snapshot_replay_then_delegation_create)
probe("SNAPREPLAY_then_ROOTVALID", snapshot_replay_then_root_valid)

server.server_close()
