# Attack-Path Engine Strategy for ADscan

## Summary
ADscan’s current local attack-path engine is limited more by **data model and search architecture** than by Python alone. The repo today loads one monolithic `attack_graph.json`, rebuilds adjacency per query, runs recursive DFS over the raw edge set, and applies several important pruning/minimization rules **after** traversal. ACL bulk edges worsen this because raw evidence and operational pathfinding edges live in the same graph.

The best long-term direction is a **phased bridge**, not an immediate full rewrite:
1. First split **raw findings** from the **operational execution graph** and move rule application earlier.
2. Introduce a stable internal graph-engine interface and benchmark a Rust-backed bridge (`rustworkx`) plus tabular precompute (`Polars`/Arrow/Parquet).
3. Only then decide whether a full PyO3/maturin Rust core is justified.

This means: **do not do the full Rust migration before fixing the graph model and pruning strategy**. If the graph remains raw/noisy and post-filtered, a faster language will still spend time traversing the wrong search space.

## Key Changes
### 1. Reframe the current bottleneck correctly
- Treat the core issue as: `single raw graph + DFS over noisy edges + post-hoc pruning`.
- Explicitly stop treating `attack_graph.json` as both:
  - the authoritative raw evidence store
  - the graph to traverse directly for all queries
- Add an engine boundary so traversal is no longer hard-coded to Python dict/list recursion.

### 2. Split graph storage into two layers
- Keep `attack_graph.json` only as the **operational graph** used for pathfinding.
- Add a separate ACL/raw-evidence store, initially file-based:
  - `acl_inventory.parquet` or `acl_inventory.jsonl` as the first milestone
  - prefer columnar layout if Polars is adopted immediately
- Raw ACL inventory must keep enough fields to re-materialize edges later:
  - source id/type/label
  - relation
  - target id/type/label
  - discovery metadata and status
- The operational graph should only contain:
  - non-noisy direct attack steps
  - derived/persisted pivots already proven useful
  - runtime/custom offensive edges used by the executor and pathfinding UX

### 3. Move pruning from post-processing into graph compilation/search
- Keep the current post-processing pipeline only for **display cleanup**.
- Move substantive pruning into one of two earlier stages:
  - **graph compilation**: remove or compress clearly redundant edges before traversal
  - **search-time pruning**: enforce rules during expansion instead of after path generation
- Current repo findings that justify this:
  - `compute_maximal_attack_paths*` in `adscan_internal/services/attack_graph_core.py` does recursive DFS with only:
    - visited-node simple-path protection
    - terminal checks
    - one local-reuse special case
  - Important logic is still later in `_apply_local_postprocessing_pipeline(...)` in `adscan_internal/services/attack_graph_service.py`, including:
    - terminal `MemberOf` trimming
    - `minimize_display_paths`
    - exact dedup
    - contained-path filtering
- The first new abstraction should be a compiled search state containing:
  - adjacency by node id
  - edge-family metadata
  - node flags (`owned`, `highvalue`, `tier0`, type)
  - precomputed membership/group closure or equivalent compressed representation
  - optional dominance/pruning caches

### 4. Introduce ACL compilation rules before changing the engine
- ACL logic should move to the **end of Phase 2**, after ADCS/access/session/custom edges exist.
- For ACL sources below a noise threshold, materialize directly into the operational graph.
- For ACL sources above the threshold, materialize only if they connect to:
  - high-value/tier-zero nodes
  - structurally important nodes (`Group`, `Computer`, `Domain`, `OU`, `GPO`, ADCS objects)
  - nodes that already have meaningful outgoing offensive edges in the operational graph
- Keep the full raw ACL inventory so later discoveries can re-promote previously suppressed ACLs.
- This avoids prematurely losing future pivots like:
  - `GenericAll -> User2` where `User2` later gains `AdminTo`, `PasswordInShare`, `LocalAdminReuse`, etc.

### 5. Build a pluggable graph-engine seam
- Add a narrow internal engine contract for:
  - graph compilation
  - path query execution
  - path reconstruction
  - optional graph statistics
- The Python engine becomes the baseline implementation behind that interface.
- Phase-1 bridge target:
  - benchmark `rustworkx` for traversal and compiled graph representation
  - benchmark `Polars` for ACL/out-degree reduction and edge projection
- Only after those benchmarks, decide whether to replace the bridge with:
  - `adscan._graphcore` via PyO3/maturin
- This preserves the product shell in Python and avoids committing to native-wheel complexity before the data model is fixed.

### 6. Long-term architecture target
- Final likely destination if benchmarks justify it:
  - Python orchestration/UI
  - compiled operational graph
  - native search core with search-time pruning and path reconstruction
- But the implementation order should be:
  1. separate raw vs operational graph
  2. compile/prune earlier
  3. benchmark bridge engine
  4. only then decide on full Rust core
- Do not make PyO3/maturin the first milestone.

## Test Plan
- Baseline profiling fixtures from real workspaces:
  - current `attack_graph.json` with ~1k, ~10k, and ACL-heavy domains
  - one owned user with no useful paths
  - one user that reaches a noisy ACL source
  - domain/all-principals mode
- Functional parity tests:
  - same visible attack paths before/after engine seam for non-noisy domains
  - same path semantics for runtime-added custom edges
  - same handling of membership stitching and local-reuse compressed edges
- Noise-control tests:
  - noisy ACL source below threshold → all ACLs promoted
  - noisy ACL source above threshold → only strategic edges promoted to operational graph
  - later custom edge added → previously suppressed ACL edge becomes promotable
- Performance acceptance:
  - separate timings for:
    - load/compile graph
    - traversal
    - post-display cleanup
  - compare:
    - current Python DFS on raw graph
    - Python on compiled operational graph
    - rustworkx bridge on compiled operational graph
- Regression tests for current pruning semantics:
  - simple-path/no repeated nodes
  - terminal `MemberOf` trimming
  - redundant membership minimization
  - contained-path behavior for domain vs principals scopes

## Assumptions
- Chosen direction for now: **phased bridge**, not immediate full Rust-core implementation.
- Packaging constraint for first milestone: **low complexity**; avoid introducing a custom native build matrix before benchmarks prove it is needed.
- The biggest near-term win is expected from **graph compilation and ACL sanitization design**, not from replacing Python syntax with Rust while keeping the same raw-graph traversal model.
- `attack_graph.json` should remain the operator-facing, pathfinding-ready graph; raw ACL bulk evidence should move to a separate store.
