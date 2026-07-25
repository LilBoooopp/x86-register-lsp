"""
Per-document state: parsed assembly, register simulation, initial values.
"""

from dataclasses import dataclass, field

from server.parser import parse_assembly, ParsedBlock
from server.simulator import simulate, SimulationResult


@dataclass
class DocumentState:
    """All state for one open assembly file."""

    uri: str
    source: str = ""
    parsed: ParsedBlock | None = None
    simulation: SimulationResult | None = None
    initial_regs: dict[str, int] = field(default_factory=dict)

    def update_source(self, source: str) -> None:
        """Called on didOpen / didChange. Reparses but does NOT auto-simulate."""
        self.source = source
        self.parsed = parse_assembly(source)

        # auto-apply @reg directives
        if self.parsed and self.parsed.register_directives:
            self.initial_regs = {**self.parsed.register_directives}
        else:
            self.initial_regs = {}

        # clear stale simulation (user must re-run)
        self.simulation = None

    def run_simulation(self) -> None:
        """Execute the simulation with current initial register values."""
        if not self.parsed or not self.parsed.instructions:
            self.simulation = None
            return
        self.simulation = simulate(self.parsed, self.initial_regs)

    def set_initial_reg(self, reg: str, value: int) -> None:
        """Set one initial register value and re-simulate."""
        self.initial_regs[reg] = value
        self.run_simulation()

    def snapshot_at_line(self, line: int) -> dict | None:
        """
        Return register state at the given 0-based line number.
        Finds the most recent instruction on or before that line.
        """
        if not self.simulation or not self.parsed:
            return None

        for snap in reversed(self.simulation.snapshots):
            inst = self.parsed.instructions[snap.instruction_index]
            if inst.line_number - 1 <= line:
                return {
                    "values": snap.values,
                    "changed": snap.changed,
                    "instruction_index": snap.instruction_index,
                    "stack": snap.stack,
                }
        return None
