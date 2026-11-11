"""Collector registry.

Each collector implements a single OSINT stage.  The registry maps stage
names to classes, and the pipeline resolves stage order from the registry.
"""

from .base import Collector, register
from .web_check import WebCheckCollector
from .openosint_actors import OpenOsintActorsCollector


class DigitalFootprintCollector(Collector):
    kind = "recon"


class BreachIntelCollector(Collector):
    kind = "breach"


class PublicRecordsCollector(Collector):
    kind = "records"


class IdentityResolutionCollector(Collector):
    kind = "identity"


class WebArchiveCollector(Collector):
    kind = "archive"


_REGISTRY = {
    DigitalFootprintCollector.kind: DigitalFootprintCollector,
    BreachIntelCollector.kind: BreachIntelCollector,
    PublicRecordsCollector.kind: PublicRecordsCollector,
    IdentityResolutionCollector.kind: IdentityResolutionCollector,
    WebArchiveCollector.kind: WebArchiveCollector,
    "web-check": WebCheckCollector,
    "openosint-actors": OpenOsintActorsCollector,
}


STAGE_ORDER = [
    "recon",
    "breach",
    "records",
    "identity",
    "archive",
    "web-check",
    "openosint-actors",
]


def get_stage_order(shuffle: bool = False) -> list[str]:
    if shuffle:
        import random
        order = STAGE_ORDER[:]
        random.shuffle(order)
        return order
    return STAGE_ORDER


def build_collector_registry() -> dict[str, type[Collector]]:
    return dict(_REGISTRY)


def get_collector(name: str) -> type[Collector]:
    return _REGISTRY.get(name)
