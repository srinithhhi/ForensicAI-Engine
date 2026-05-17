"""Adversary simulation layer (dev-only).

Only lightweight base classes are re-exported here. Concrete simulators like
`AtomicRedTeamRunner` should be imported from their own modules
(`from simulation.atomic_runner import AtomicRedTeamRunner`) so that
`python -m simulation.ssh_client` doesn't trigger a double-import.
"""

from simulation.base import Simulator, SimulationManifest, TechniqueRun

__all__ = ["Simulator", "SimulationManifest", "TechniqueRun"]
