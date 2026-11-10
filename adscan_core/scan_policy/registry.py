"""Runtime access to the generated check registry.

Every consumer (engine gates, policy resolver, report, web backend) reads the
registry through :func:`load_registry`. Nothing computes a second registry at
runtime; the engine-side builder only regenerates ``registry_data`` and a drift
test proves the committed snapshot is current.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Iterable

from adscan_core.scan_policy import registry_data
from adscan_core.scan_policy.families import FAMILIES, Family
from adscan_core.scan_policy.model import CheckDefinition


def _norm(value: str) -> str:
    return str(value or "").strip().lower()


class CheckRegistry:
    """Indexed, read-only view over the generated check list."""

    def __init__(
        self,
        *,
        version: int,
        checks: Iterable[CheckDefinition],
        retired: dict[str, str | None],
        non_check_relations: Iterable[str],
    ) -> None:
        self.version = int(version)
        self.checks: tuple[CheckDefinition, ...] = tuple(checks)
        self.retired = dict(retired)
        self.non_check_relations: frozenset[str] = frozenset(
            _norm(r) for r in non_check_relations
        )
        self.families: tuple[Family, ...] = FAMILIES
        self._by_id = {c.check_id: c for c in self.checks}
        self._by_relation: dict[str, CheckDefinition] = {}
        self._by_finding: dict[str, CheckDefinition] = {}
        self._by_subphase: dict[str, CheckDefinition] = {}
        self._by_cve: dict[str, CheckDefinition] = {}
        self._by_job: dict[str, CheckDefinition] = {}
        self._by_phase: dict[str, list[CheckDefinition]] = {}
        for check in self.checks:
            for rel in check.relations:
                self._by_relation[_norm(rel)] = check
            for key in check.finding_keys:
                self._by_finding[_norm(key)] = check
            for sub in check.subphases:
                self._by_subphase[_norm(sub)] = check
            for cve in check.cve_ids:
                self._by_cve[_norm(cve)] = check
            for job in check.jobs:
                self._by_job[_norm(job)] = check
            for phase in check.phases:
                self._by_phase.setdefault(_norm(phase), []).append(check)

    # ── lookups ──────────────────────────────────────────────────────────
    def get(self, check_id: str) -> CheckDefinition | None:
        return self._by_id.get(str(check_id or "").strip())

    def __contains__(self, check_id: object) -> bool:
        return isinstance(check_id, str) and check_id in self._by_id

    def check_for_relation(self, relation: str) -> CheckDefinition | None:
        """The technique check gating an attack-step relation (aliases folded)."""
        return self._by_relation.get(_norm(relation))

    def check_for_finding(self, key: str) -> CheckDefinition | None:
        return self._by_finding.get(_norm(key))

    def check_for_subphase(self, phase_id: str, subphase_id: str) -> CheckDefinition | None:
        return self._by_subphase.get(_norm(f"{phase_id}.{subphase_id}"))

    def check_for_cve(self, cve_id: str) -> CheckDefinition | None:
        return self._by_cve.get(_norm(cve_id))

    def check_for_job(self, kind: str) -> CheckDefinition | None:
        return self._by_job.get(_norm(kind))

    def checks_for_phase(self, phase_id: str) -> tuple[CheckDefinition, ...]:
        """Every check bound to a whole phase or to one of its subphases."""
        bound = list(self._by_phase.get(_norm(phase_id), ()))
        prefix = _norm(phase_id) + "."
        for key, check in self._by_subphase.items():
            if key.startswith(prefix) and check not in bound:
                bound.append(check)
        return tuple(bound)

    def checks_in_family(self, family_id: str) -> tuple[CheckDefinition, ...]:
        return tuple(c for c in self.checks if c.family == family_id)

    def is_known_relation(self, relation: str) -> bool:
        """True for any catalog relation (a check or a non-check relation)."""
        key = _norm(relation)
        return key in self._by_relation or key in self.non_check_relations


@lru_cache(maxsize=1)
def load_registry() -> CheckRegistry:
    """Return the registry built from the committed snapshot (cached)."""
    return CheckRegistry(
        version=registry_data.REGISTRY_VERSION,
        checks=(CheckDefinition.from_mapping(c) for c in registry_data.CHECKS),
        retired=dict(registry_data.RETIRED),
        non_check_relations=registry_data.NON_CHECK_RELATIONS,
    )


__all__ = ("CheckRegistry", "load_registry")
