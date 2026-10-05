"""
Specification-derived state-transition engine for the TUF TSTM study.

Replaces the previous hand-authored `_DEFAULT_REACHABLE_NEXT` adjacency
table in tstm_analysis.py (flagged, by this module's own prior docstring,
as "a STARTING-POINT EXAMPLE... must be reviewed against the real
RepositorySimulator behavior before being treated as final" -- and, per
external review, never actually reviewed). This module instead defines an
explicit, finite abstract state space and, for each of the 12 frozen
transitions, a precondition (is this transition meaningfully constructible
from this state?) and an effect (resulting state + expected ACCEPT/REJECT),
each traceable to a spec clause or to this study's own property definitions
(P1-P5) that were themselves derived from spec text (see PAPER_DRAFT.md
Sec.5). reachable_ordered_pairs/triples/quadruples are then computed by
mechanically enumerating this state machine via breadth-first search from
the frozen initial state, up to the K<=4 core-family depth bound -- not by
hand-picking which pairs "seem" reachable.

THE KEY MODELING FIX this engine makes over the old hand table: a REJECTed
transition leaves state UNCHANGED, rather than being treated as a terminal/
absorbing dead end. The old table set every REJECT-outcome transition's
reachable-next set to `set()`, which made "reject -> recovery" compositions
(e.g. this study's redesigned P1: a valid rotation, then a rejected bad
attempt, then a further valid rotation) structurally unreachable by
construction -- not because they are not real TUF sequences (P1's real
execution against both python-tuf and go-tuf v2 proves they are), but
because the old table conflated "the attempted transition was rejected"
with "no further transition can follow it", which are different claims.
This engine keeps them distinct: rejection is a property of the transition
attempted, not of what can be attempted next.

State-minimality: the persistent state actually needed to decide every
transition's precondition in this alphabet turns out to be five booleans/
enums, not the full eight PAPER_DRAFT.md Sec.3 state variables at full
generality -- because the fully-general variables (root version number,
key set contents, etc.) only ever matter, for THESE 12 transitions'
preconditions, through their "has this class of event ever happened yet"
projection. The five are re-expressed onto the original eight-variable
naming (R_v, R_K, R_t, T_v, S_v, G_v, D, E) in AbstractState.as_named_state()
for compatibility with the sequence_corpus schema's state-variable names.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable, NamedTuple


class Decision(NamedTuple):
    label: str  # "ACCEPT" or "REJECT" -- REJECT means the transition's
    #  attempt is expected to be rejected by a conforming client; ACCEPT
    #  means it is expected to be accepted and to advance state.


ACCEPT, REJECT = Decision("ACCEPT"), Decision("REJECT")


@dataclass(frozen=True)
class AbstractState:
    """Finite, bounded abstract state. Each field is exactly the derived
    fact at least one transition's precondition below actually depends on --
    no decorative fields (state-minimality, matching PAPER_DRAFT.md Sec.3's
    own stated principle, applied honestly to what the engine needs rather
    than asserted without a mechanically-checkable engine behind it)."""
    root_ever_validly_rotated: bool = False  # gates METADATA_BY_REMOVED_KEY:
    #   a "removed key" to sign with can only exist once at least one prior
    #   valid rotation has superseded an earlier key (Sec.5.3.4 context).
    timestamp_ever_advanced: bool = False  # gates TIMESTAMP_REPLAY: replaying
    #   an "earlier" version presupposes a later one has been seen (Sec.5.4.3.1/5.5.5).
    snapshot_ever_advanced: bool = False  # gates SNAPSHOT_REPLAY, same reasoning.
    delegation: str = "ABSENT"  # ABSENT | ACTIVE | REMOVED -- gates the
    #   DELEGATION_CREATE / DELEGATION_REMOVE / DELEGATED_REPLAY_AFTER_REMOVAL
    #   lifecycle; a delegation must exist to be removed, and must have been
    #   removed to be replayed.
    expired: bool = False  # True once EXPIRE has been applied (targets
    #   TIMESTAMP's `expires` field specifically -- see the EXPIRE rule
    #   below). Read two ways: (a) state-trace naming (as_named_state, E),
    #   and (b) ADDED this round, the global blocking override in
    #   apply_transition -- an empirically-probed fact
    #   (probe_cross_role_blocking3.py), not an assumption: an expired
    #   `expires` field persists across ordinary republishes of that role
    #   (unlike a version-ordering replay, which self-heals on the next
    #   ordinary publish -- see TIMESTAMP_REPLAY/SNAPSHOT_REPLAY below,
    #   which do NOT need an analogous flag because their executors
    #   explicitly self-heal immediately, confirmed empirically not to
    #   contaminate a following transition when they do). No transition in
    #   this 12-symbol alphabet clears `expired` once set -- there is no
    #   "un-expire" transition -- an honest, load-bearing fact about this
    #   alphabet's limits, not an oversight (see PAPER_DRAFT.md).
    root_blocked: bool = False  # CORRECTED/ADDED this round, before the full
    #   52-pair batch, after empirically probing (not assuming) whether a
    #   rejected root transition affects only root, or everything downstream.
    #   It affects everything: TUF's client update procedure verifies
    #   root -> timestamp -> snapshot -> targets/delegations IN ORDER, and a
    #   client whose root is stuck on an invalid not-yet-superseded version
    #   (Sec.5.3.5's strict sequential requirement) never reaches the later
    #   stages at all, regardless of whether their own content is
    #   individually valid. Empirically confirmed:
    #   probe_cross_role_blocking.py (ROOT_ROTATE_SKIP then a perfectly
    #   ordinary TIMESTAMP_ADVANCE -> REJECT, both real clients). Cleared
    #   only by a subsequent ROOT_ROTATE_VALID (which, per Section 5's
    #   already-documented "replace, not append" fix, is itself the one
    #   transition proven able to actually clear it).

    def as_named_state(self) -> dict:
        """Project onto the sequence_corpus schema's 8 named state
        variables (R_v, R_K, R_t, T_v, S_v, G_v, D, E), using the same
        symbolic BOUNDARY_STATES vocabulary already used elsewhere in this
        package, so this engine's states are directly comparable to
        expected_state_trace entries in the real corpus."""
        return {
            "R_v": "VERSION_NEXT" if self.root_ever_validly_rotated else "VERSION_CURRENT",
            "R_K": "KEY_FULL_REPLACEMENT" if self.root_ever_validly_rotated else "KEY_ACTIVE",
            "R_t": "THRESHOLD_EXACT",
            "T_v": "VERSION_NEXT" if self.timestamp_ever_advanced else "VERSION_CURRENT",
            "S_v": "VERSION_NEXT" if self.snapshot_ever_advanced else "VERSION_CURRENT",
            "G_v": "VERSION_CURRENT",
            "D": {"ABSENT": "DELEGATION_ABSENT", "ACTIVE": "DELEGATION_ACTIVE",
                  "REMOVED": "DELEGATION_REMOVED"}[self.delegation],
            "E": "EXPIRATION_EXPIRED" if self.expired else "EXPIRATION_VALID",
        }


INITIAL_STATE = AbstractState()

Rule = tuple[Callable[[AbstractState], bool], Decision, Callable[[AbstractState], AbstractState]]

# ---------------------------------------------------------------------------
# One rule per transition in the frozen 12-symbol alphabet (tstm_analysis.
# TRANSITIONS). Each entry: (precondition, expected_decision, effect).
# effect is applied only on ACCEPT; on REJECT the state is defined to be
# unchanged (see module docstring -- this is the actual fix over the old
# hand table, not an incidental detail).
# ---------------------------------------------------------------------------
_RULES: dict[str, Rule] = {
    # Sec.5.3.4: a root rotation must be signed to satisfy BOTH the
    # old-threshold and the new-threshold. A rotation constructed to
    # actually satisfy both (as this study's real p1_case/p4_case dual-sign
    # constructions do) is always constructible and always expected ACCEPT.
    "ROOT_ROTATE_VALID": (
        lambda s: True, ACCEPT,
        lambda s: replace(s, root_ever_validly_rotated=True),
    ),
    # Sec.5.3.5: root versions must be adopted sequentially, one at a time;
    # a server-side version skip is always constructible and always
    # expected REJECT.
    "ROOT_ROTATE_SKIP": (lambda s: True, REJECT, lambda s: s),
    # Sec.5.3.4 violation (missing old- or new-threshold signature); always
    # constructible, always expected REJECT.
    "ROOT_ROTATE_INSUF_THRESHOLD": (lambda s: True, REJECT, lambda s: s),
    # Composed property (P4): a role's signature-verification logic operates
    # only over the CURRENTLY-authorized key set (Sec.5.3.4's own logic,
    # composed forward in time) -- so metadata signed only by a since-removed
    # key can only be constructed once a prior valid rotation has actually
    # superseded a key. Precondition: root_ever_validly_rotated.
    "METADATA_BY_REMOVED_KEY": (
        lambda s: s.root_ever_validly_rotated, REJECT, lambda s: s,
    ),
    "TIMESTAMP_ADVANCE": (
        lambda s: True, ACCEPT, lambda s: replace(s, timestamp_ever_advanced=True),
    ),
    # Sec.5.4.3.1/5.5.5 rollback protection: replaying an earlier timestamp
    # version presupposes a later one has already been seen and trusted.
    "TIMESTAMP_REPLAY": (lambda s: s.timestamp_ever_advanced, REJECT, lambda s: s),
    "SNAPSHOT_ADVANCE": (
        lambda s: True, ACCEPT, lambda s: replace(s, snapshot_ever_advanced=True),
    ),
    "SNAPSHOT_REPLAY": (lambda s: s.snapshot_ever_advanced, REJECT, lambda s: s),
    "DELEGATION_CREATE": (
        lambda s: s.delegation == "ABSENT", ACCEPT, lambda s: replace(s, delegation="ACTIVE"),
    ),
    "DELEGATION_REMOVE": (
        lambda s: s.delegation == "ACTIVE", ACCEPT, lambda s: replace(s, delegation="REMOVED"),
    ),
    # Composed property (P5): a role's authorization is checked at the time
    # it is used, not cached from before removal -- so replaying it
    # presupposes it has actually been removed already.
    "DELEGATED_REPLAY_AFTER_REMOVAL": (
        lambda s: s.delegation == "REMOVED", REJECT, lambda s: s,
    ),
    # CORRECTED (this round, before generating the full 52-pair batch --
    # caught by re-reading tuf-conformance's own test_expiration.py rather
    # than by a real-client mismatch, which is the more expensive way to
    # find a wrong model rule). Originally modeled as an environmental,
    # always-ACCEPT transition ("time just passes"). But EXPIRE, to be
    # executable and observable at all, must correspond to an actual
    # client refresh() attempt against metadata whose declared `expires`
    # field is already in the past -- and per spec Sec.5.3.10/5.4.3.5/etc.
    # and tuf-conformance's own test_timestamp_expired/test_snapshot_expired
    # (which construct exactly this: `repo.<role>.expires =
    # get_date_n_days_in_past(N)` then `publish()`, with NO faketime
    # involved -- the server publishes already-expired content, checked
    # against the client's real wall clock), the correct expected decision
    # is REJECT, not ACCEPT. Sets `expired=True` regardless of the general
    # "REJECT leaves state unchanged" convention (apply_transition special-
    # cases this, like ROOT_ROTATE_SKIP/INSUF_THRESHOLD/METADATA_BY_REMOVED_KEY
    # special-case setting root_blocked=True) -- because `expired`'s
    # persistence, unlike a merely-rejected single attempt, is the entire
    # empirical finding this field exists to capture.
    "EXPIRE": (lambda s: True, REJECT, lambda s: s),
}

TRANSITIONS: list[str] = list(_RULES.keys())
assert len(TRANSITIONS) == 12, "engine must cover exactly the frozen 12-transition alphabet"

# Root-family transitions whose REJECT sets the persistent, everything-
# blocking root_blocked flag (empirically probed, not assumed -- module
# docstring / AbstractState.root_blocked). ROOT_ROTATE_VALID is excluded:
# it is the one transition that CLEARS the flag, never sets it.
_ROOT_BLOCKING_REJECTS = {"ROOT_ROTATE_SKIP", "ROOT_ROTATE_INSUF_THRESHOLD", "METADATA_BY_REMOVED_KEY"}


def apply_transition(state: AbstractState, transition_type: str) -> tuple[AbstractState, Decision] | None:
    """Returns (resulting_state, decision) if transition_type is
    meaningfully constructible from `state` (precondition holds), else None.

    Two layers, in order:
    1. GLOBAL BLOCKING OVERRIDE (added this round, empirically probed via
       probe_cross_role_blocking{,2,3}.py, not assumed): if the client is
       currently root_blocked or has seen an uncleared `expired` metadata
       version, EVERY transition except the one specific recovery
       transition (ROOT_ROTATE_VALID, for root_blocked only -- nothing
       clears `expired`) is forced to REJECT with state unchanged,
       regardless of that transition's own nominal rule. This is what
       makes e.g. (ROOT_ROTATE_SKIP, TIMESTAMP_ADVANCE) correctly predict
       (REJECT, REJECT) rather than the nominal-rule-only (REJECT, ACCEPT)
       that an earlier version of this engine (and the 10-pair root-family-
       only batch, which never exercised a root-blocks-non-root pair)
       would have predicted.
    2. Otherwise, the transition's own nominal (precondition, decision,
       effect) from `_RULES` applies, with root_blocked/expired set on the
       *outcome* side for the specific transitions that establish them
       (see _ROOT_BLOCKING_REJECTS and EXPIRE), overriding the general
       "REJECT leaves state unchanged" convention for exactly those two
       fields -- everything else about REJECT-leaves-state-unchanged still
       holds.
    """
    precondition, decision, effect = _RULES[transition_type]
    if not precondition(state):
        return None

    if state.root_blocked and transition_type != "ROOT_ROTATE_VALID":
        return state, REJECT
    if state.expired:
        return state, REJECT

    if transition_type == "ROOT_ROTATE_VALID":
        new_state = replace(effect(state), root_blocked=False)
        return new_state, ACCEPT
    if transition_type in _ROOT_BLOCKING_REJECTS:
        return replace(state, root_blocked=True), REJECT
    if transition_type == "EXPIRE":
        return replace(state, expired=True), REJECT

    return (effect(state) if decision is ACCEPT else state), decision


def reachable_next(state: AbstractState) -> set[str]:
    """Every transition whose precondition holds in `state` -- i.e. every
    transition that could meaningfully be attempted next, REJECT-outcome
    ones included (they are constructible attempts, just expected to fail)."""
    return {t for t in TRANSITIONS if _RULES[t][0](state)}


def enumerate_reachable_sequences(max_depth: int, initial_state: AbstractState = INITIAL_STATE
                                   ) -> dict[int, set[tuple[str, ...]]]:
    """Mechanical BFS enumeration of every reachable ordered transition
    sequence up to max_depth, grouped by length. This is the direct
    replacement for the old hand-authored _DEFAULT_REACHABLE_NEXT: pairs are
    `result[2]`, triples are `result[3]`, etc. Exhaustive and deterministic
    over the finite abstract state space defined above -- not sampled, not
    hand-picked after seeing results (the study's own stated
    reachability-denominator requirement)."""
    by_length: dict[int, set[tuple[str, ...]]] = {n: set() for n in range(1, max_depth + 1)}
    frontier: list[tuple[tuple[str, ...], AbstractState]] = [((), initial_state)]
    for depth in range(1, max_depth + 1):
        next_frontier = []
        for prefix, state in frontier:
            for t in reachable_next(state):
                new_state, _decision = apply_transition(state, t)
                seq = prefix + (t,)
                by_length[depth].add(seq)
                next_frontier.append((seq, new_state))
        frontier = next_frontier
    return by_length


def reachable_ordered_pairs(max_depth: int = 4) -> set[tuple[str, str]]:
    """C2 denominator, mechanically derived: every (A, B) such that some
    reachable length-2 sequence starts with A immediately followed by B."""
    seqs = enumerate_reachable_sequences(max(2, max_depth))
    return set(seqs[2])


def reachable_ordered_triples(max_depth: int = 4) -> set[tuple[str, str, str]]:
    """C3 denominator, mechanically derived, matching tstm_analysis's prior
    CORE-family restriction is applied by the caller (this function returns
    the full triple set; tstm_analysis.reachable_ordered_triples filters
    it to core-relevant transitions, same as before)."""
    seqs = enumerate_reachable_sequences(max(3, max_depth))
    return set(seqs[3])


# ---------------------------------------------------------------------------
# Self-validation: replay every REAL executed sequence in this study's
# corpus (P1, P1_CONTROL, P2, P4, P5, and the 2 BASELINE_MAPPED P3 cases)
# through this engine and assert its predicted decisions match the actually-
# observed real-client decisions recorded in
# tuf_study/example_data/REAL_execution_results.SCHEMA.json. This is the
# "engine'i doğrulayın" step requested before any coverage recomputation.
# ---------------------------------------------------------------------------
REAL_SEQUENCES_FOR_VALIDATION: dict[str, list[str]] = {
    "P1": ["ROOT_ROTATE_VALID", "ROOT_ROTATE_INSUF_THRESHOLD", "ROOT_ROTATE_VALID"],
    "P1_CONTROL": ["ROOT_ROTATE_INSUF_THRESHOLD"],
    "P2": ["ROOT_ROTATE_SKIP"],
    "P4": ["ROOT_ROTATE_VALID", "METADATA_BY_REMOVED_KEY"],
    "P5": ["DELEGATION_CREATE", "DELEGATION_REMOVE", "DELEGATED_REPLAY_AFTER_REMOVAL"],
    "P3_timestamp": ["TIMESTAMP_ADVANCE", "TIMESTAMP_REPLAY"],
    "P3_snapshot": ["SNAPSHOT_ADVANCE", "SNAPSHOT_REPLAY"],
}
# Real, actually-observed decision for each K-counted step above, transcribed
# from REAL_execution_results.SCHEMA.json / REAL_REPORT.md (identical on
# both python-tuf and go-tuf v2 in every case in this study so far).
REAL_OBSERVED_DECISIONS: dict[str, list[str]] = {
    "P1": ["ACCEPT", "REJECT", "ACCEPT"],
    "P1_CONTROL": ["REJECT"],
    "P2": ["REJECT"],
    "P4": ["ACCEPT", "REJECT"],
    "P5": ["ACCEPT", "ACCEPT", "REJECT"],
    "P3_timestamp": ["ACCEPT", "REJECT"],
    "P3_snapshot": ["ACCEPT", "REJECT"],
}


def validate_against_real_data() -> list[str]:
    """Returns a list of mismatch descriptions (empty list == fully
    validated). Run at import time below; raises if anything mismatches, so
    this module cannot be silently used for coverage computation while
    failing its own validation against real data."""
    mismatches = []
    for case, transitions in REAL_SEQUENCES_FOR_VALIDATION.items():
        state = INITIAL_STATE
        predicted = []
        for t in transitions:
            result = apply_transition(state, t)
            if result is None:
                mismatches.append(f"{case}: transition {t} has no defined precondition-satisfying rule from state {state}")
                break
            state, decision = result
            predicted.append(decision.label)
        else:
            expected = REAL_OBSERVED_DECISIONS[case]
            if predicted != expected:
                mismatches.append(f"{case}: engine predicted {predicted}, real clients observed {expected}")
    return mismatches


if __name__ == "__main__":
    problems = validate_against_real_data()
    if problems:
        print("VALIDATION FAILED:")
        for p in problems:
            print(" -", p)
        raise SystemExit(1)
    print(f"Validated OK against all {len(REAL_SEQUENCES_FOR_VALIDATION)} real executed sequences "
          f"(P1, P1_CONTROL, P2, P4, P5, 2x P3) -- engine predictions match real observed client decisions.")
    print()
    seqs = enumerate_reachable_sequences(4)
    for depth, s in seqs.items():
        print(f"depth {depth}: {len(s)} reachable ordered sequences")
