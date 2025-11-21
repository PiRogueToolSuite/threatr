import logging

from threatr.core.models import (
    Request,
)
from threatr.modules.module import AnalysisModule

logger = logging.getLogger(__name__)


class MISPModule(AnalysisModule):
    request: Request = None
    entities: list = []
    relations: list = []
    events: list = []
    credentials: dict = None
    vendor_response: dict = None

    def __init__(self, request: Request, credentials: dict):
        self.request = request
        self.credentials = credentials

    @classmethod
    def unique_identifier(cls) -> str:
        return "shodan"

    @classmethod
    def vendor(cls) -> str:
        return "Shodan"

    @classmethod
    def description(cls) -> str:
        return "Get intelligence from Shodan."

    @classmethod
    def supported_types(cls) -> dict[str, list[str]]:
        return {
            'observable': ['ipv4', 'ipv6', 'domain', 'hostname', 'cve', 'service'],
            'device': ['server']
        }

    def fail_fast(self) -> bool:
        return super().fail_fast()
