"""Detection modules.

Stage 4 ships the contract and a null reference implementation. Real signals
arrive later: threat intelligence (Stage 5), newly registered domains
(Stage 6), typosquatting (Stage 12), beaconing (Stage 13).
"""

from .base import DetectionModule, ModuleResult, ModuleScore, QueryContext
from .beaconing import BeaconingModule, InsufficientObservations
from .dga import DGAModule, ModelUnavailable
from .nrd import NewDomainModule
from .rdap import (RdapAgeModule, RegistrationPending, RegistrationShared,
                   RegistrationUnknown)
from .null import FixedScoreModule, NullModule
from .ti import FeedUnavailable, ThreatIntelModule
from .typosquat import BrandsUnavailable, TyposquatModule

#: Name to class, for configuration-driven construction. Real modules are
#: added here as they arrive, so DNSF_ENGINE_MODULES stays the single place
#: a configuration is expressed.
REGISTRY: dict[str, type[DetectionModule]] = {
    "null": NullModule,
    "ti": ThreatIntelModule,
    "nrd": NewDomainModule,
    "typosquat": TyposquatModule,
    "dga": DGAModule,
    "beaconing": BeaconingModule,
    "rdap": RdapAgeModule,
}

__all__ = [
    "DetectionModule",
    "ModuleResult",
    "ModuleScore",
    "QueryContext",
    "NullModule",
    "ThreatIntelModule",
    "NewDomainModule",
    "TyposquatModule",
    "DGAModule",
    "BeaconingModule",
    "RdapAgeModule",
    "RegistrationPending",
    "RegistrationShared",
    "RegistrationUnknown",
    "InsufficientObservations",
    "ModelUnavailable",
    "BrandsUnavailable",
    "FeedUnavailable",
    "FixedScoreModule",
    "REGISTRY",
]
