from bgpsimulator.shared import Prefix

from .roa import ROA


class ROASNode:
    """Node in the ROAS tree"""

    def __init__(self, prefix: Prefix | None = None, roas: set[ROA] | None = None):
        self.prefix: Prefix | None = prefix
        self.roas: set[ROA] = roas or set()
        self.left: ROASNode | None = None
        self.right: ROASNode | None = None

    def add_data(self, prefix: Prefix, roa: ROA) -> None:
        """Adds ROA to the node for that prefix"""

        self.prefix = prefix
        self.roas.add(roa)
