"""Running the comparison and rendering it.

The table reports every measure for every selector, including the ones where the
governed path loses. A comparison that only showed the measures we win on would
not be worth running.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from sim.metrics import RunResult
from sim.run import run
from sim.scenario import Scenario
from sim.selectors import Governed, Greedy, Hysteresis, StaticPriority


def default_selectors(scenario: Scenario) -> dict[str, object]:
    return {
        "greedy": Greedy(),
        "static_priority": StaticPriority(("fiber0", "lte0", "sat0", "fso0")),
        "hysteresis": Hysteresis(dwell_s=300.0),
        "governed": Governed(scenario.bundle, site_id=scenario.site_id),
    }


@dataclass
class ComparisonTable:
    rows: list[RunResult] = field(default_factory=list)

    def _for(self, selector: str) -> list[RunResult]:
        return [r for r in self.rows if r.selector == selector]

    def violations(self, selector: str) -> int:
        return sum(r.violation_count for r in self._for(selector))

    def downtime(self, selector: str) -> int:
        return sum(r.downtime_s for r in self._for(selector))

    def refused(self, selector: str) -> int:
        return sum(r.refused_s for r in self._for(selector))

    def flaps(self, selector: str) -> int:
        return sum(r.flaps for r in self._for(selector))

    def cost(self, selector: str) -> float:
        return sum(r.cost for r in self._for(selector))

    def degraded(self, selector: str) -> int:
        return sum(r.degraded_s for r in self._for(selector))

    def selectors(self) -> list[str]:
        seen: list[str] = []
        for row in self.rows:
            if row.selector not in seen:
                seen.append(row.selector)
        return seen

    def scenarios(self) -> list[str]:
        seen: list[str] = []
        for row in self.rows:
            if row.scenario not in seen:
                seen.append(row.scenario)
        return seen

    def cell(self, scenario: str, selector: str) -> dict[str, float]:
        rows = [r for r in self.rows if r.scenario == scenario and r.selector == selector]
        return {
            "violations": sum(r.violation_count for r in rows),
            "downtime_s": sum(r.downtime_s for r in rows),
            "refused_s": sum(r.refused_s for r in rows),
            "flaps": sum(r.flaps for r in rows),
            "cost": sum(r.cost for r in rows),
            "degraded_s": sum(r.degraded_s for r in rows),
        }


def compare(
    scenarios: Iterable[Scenario], seeds: Iterable[int] = range(5), selectors=None
) -> ComparisonTable:
    table = ComparisonTable()
    for scenario in scenarios:
        built = selectors(scenario) if selectors else default_selectors(scenario)
        for name, selector in built.items():
            for seed in seeds:
                result = run(scenario, selector, seed=seed)
                result.selector = name
                table.rows.append(result)
    return table


def render_markdown(table: ComparisonTable) -> str:
    lines = []
    for scenario in table.scenarios():
        lines.append(f"### {scenario}\n")
        lines.append(
            "| selector | violations | link down (s) | refused (s) | flaps | "
            "overage cost | degraded (s) |"
        )
        lines.append("|---|---:|---:|---:|---:|---:|---:|")
        for selector in table.selectors():
            c = table.cell(scenario, selector)
            lines.append(
                f"| {selector} | {c['violations']} | {c['downtime_s']} | "
                f"{c['refused_s']} | {c['flaps']} | "
                f"{c['cost']:.2f} | {c['degraded_s']} |"
            )
        lines.append("")
    return "\n".join(lines)
