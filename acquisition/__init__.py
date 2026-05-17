"""Acquisition layer — per-scope evidence collectors.

Only lightweight base classes are re-exported here. Concrete acquirers like
`BareMetalAcquirer` should be imported from their own modules
(`from acquisition.bare_metal_acquirer import BareMetalAcquirer`) so that
`python -m acquisition.velociraptor_client` doesn't trigger a double-import.
"""

from acquisition.base import Acquirer, AcquisitionManifest, StepResult

__all__ = ["Acquirer", "AcquisitionManifest", "StepResult"]
