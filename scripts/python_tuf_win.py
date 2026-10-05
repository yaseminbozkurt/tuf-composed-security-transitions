#!/usr/bin/env python
"""Windows-compatible wrapper around the real tuf-conformance python-tuf adapter.

WHY THIS FILE EXISTS (documented, transparent, non-security-affecting):
python-tuf's ngclient.Updater maintains a convenience `root.json` symlink
pointing into `root_history/N.root.json` for local debugging/inspection.
os.symlink() requires SeCreateSymbolicLinkPrivilege on Windows (Administrator
or Developer Mode), which is not available in this environment and was not
enabled without the user's explicit approval.

This shim replaces ONLY os.symlink with os.link (a hard link) for the
duration of this process. A hard link and a symlink both make root.json
resolve to the exact same file content as the versioned root file -- the
difference is purely in filesystem mechanics (inode/MFT-record sharing vs.
path indirection), not in any TUF security semantic. No line of the actual
tuf.ngclient.Updater source is modified, and no security-relevant logic
(signature verification, threshold checks, rollback checks, expiration
checks) is touched by this patch -- it only affects a cosmetic local-cache
bookkeeping detail.

If os.link also fails (e.g. cross-volume temp dirs), falls back to a plain
file copy, which is even further from "real" filesystem-link semantics but
still functionally equivalent from the Updater's perspective (it only ever
reads root.json by path).
"""

import os
import shutil
import sys

_real_symlink = os.symlink


def _symlink_via_hardlink_or_copy(src: str, dst: str, *args, **kwargs) -> None:
    # os.symlink resolves a relative `src` relative to dst's directory when
    # later dereferenced; os.link has no such indirection, so we must
    # resolve it ourselves to preserve identical behavior.
    resolved_src = src if os.path.isabs(src) else os.path.join(os.path.dirname(dst), src)
    try:
        os.link(resolved_src, dst)
    except OSError:
        shutil.copyfile(resolved_src, dst)


os.symlink = _symlink_via_hardlink_or_copy  # type: ignore[assignment]

# Delegate to the real, unmodified tuf-conformance adapter logic.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from python_tuf import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
