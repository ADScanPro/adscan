"""Workspace-persisted queue of spray combos deferred for lockout proximity.

Each entry is one (user, password, spray_type) plus the earliest epoch it is
safe to spray (the user's ``badPasswordTime`` + ``lockOutObservationWindow``).
Dedup is case-insensitive on user, case-sensitive on password — matching the
granular spray history. Persisted alongside the other workspace state so a
later session / the reconciliation phase can drain it.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DeferredSprayCombo:
    user: str
    password: str
    spray_type: str
    earliest_safe_epoch: float | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.user.casefold(), self.password)


@dataclass
class DeferredSprayQueue:
    combos: list[DeferredSprayCombo] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.combos)

    def upsert(self, combo: DeferredSprayCombo) -> None:
        for i, existing in enumerate(self.combos):
            if existing.key == combo.key and existing.spray_type == combo.spray_type:
                self.combos[i] = combo
                return
        self.combos.append(combo)

    def earliest_reset_epoch(self) -> float | None:
        epochs = [c.earliest_safe_epoch for c in self.combos if c.earliest_safe_epoch is not None]
        return min(epochs) if epochs else None

    def to_dict(self) -> dict:
        return {
            "schema_version": "deferred-spray-1",
            "combos": [
                {"user": c.user, "password": c.password, "spray_type": c.spray_type,
                 "earliest_safe_epoch": c.earliest_safe_epoch}
                for c in self.combos
            ],
        }

    @classmethod
    def from_dict(cls, data: dict | None) -> "DeferredSprayQueue":
        q = cls()
        for row in (data or {}).get("combos", []) or []:
            try:
                q.upsert(DeferredSprayCombo(
                    user=str(row["user"]), password=str(row["password"]),
                    spray_type=str(row["spray_type"]),
                    earliest_safe_epoch=row.get("earliest_safe_epoch"),
                ))
            except Exception:  # noqa: BLE001
                continue
        return q
