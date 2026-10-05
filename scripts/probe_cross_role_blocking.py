"""Probe: does a permanently-stuck (unrecovered) root block subsequent
timestamp/snapshot refreshes entirely, or are they verified independently?
Must know this before building the full 52-pair executor -- if blocking,
every non-root transition following an unrecovered root REJECT needs its
own "blocked" precondition in state_engine.py, not just root transitions."""
import os
import sys

EXPERIMENT_DIR = r"C:\Users\yasemin.bozkurt\tuf_experiment"
CONFORMANCE_DIR = os.path.join(EXPERIMENT_DIR, "tuf-conformance")
sys.path.insert(0, CONFORMANCE_DIR)

from tuf.api.metadata import Root, Timestamp
from tuf_conformance._internal.client_runner import ClientRunner
from tuf_conformance._internal.simulator_server import SimulatorServer

PYTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "python-tuf", "run_python_tuf.bat")
GOTUF_ENTRY = os.path.join(CONFORMANCE_DIR, "clients", "go-tuf", "go-tuf.exe")
IMPLS = {"python-tuf": PYTUF_ENTRY, "go-tuf-v2": GOTUF_ENTRY}

server = SimulatorServer(None)
for impl_name, entry in IMPLS.items():
    test_name = f"PROBE_{impl_name}"
    client = ClientRunner(entry, server, test_name)
    init_data, repo = server.new_test(test_name)
    assert client.init_client(init_data) == 0
    r0 = client.refresh(init_data)  # baseline, v1

    # ROOT_ROTATE_SKIP: force an unrecoverable root version skip
    repo.root.version += 1
    repo.rotate_keys(Root.type)
    repo.publish([Root.type], verify_version=False)
    r1 = client.refresh(init_data)  # expect REJECT -- root now permanently stuck

    # Now attempt a perfectly ordinary, valid TIMESTAMP_ADVANCE
    repo.publish([Timestamp.type])
    r2 = client.refresh(init_data)  # does THIS fail too, or succeed independently?

    print(f"{impl_name}: baseline={r0} root_skip={r1} timestamp_advance_after_stuck_root={r2}")

server.server_close()
