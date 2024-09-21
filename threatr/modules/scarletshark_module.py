import json
import logging
from scarlet_shark_client.client import ClientFactory
import pytz
from dateutil.parser import parse

from threatr.core.models import (
    Entity,
    EntityRelation,
    Request,
    EntitySuperType,
    EntityType,
    Event,
)
from threatr.modules.module import AnalysisModule

logger = logging.getLogger(__name__)


class ScarletShark(AnalysisModule):
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
        return "scarlet_shark"

    @classmethod
    def vendor(cls) -> str:
        return "ScarletShark"

    @classmethod
    def description(cls) -> str:
        return "Get intelligence from ScarletShark."

    @classmethod
    def supported_types(cls) -> dict[str, list[str]]:
        return {
            'observable': ['ipv4', 'ipv6', 'domain', 'sha256', 'url']
        }

    def fail_fast(self) -> bool:
        return super().fail_fast()

    def execute_request(self) -> dict:
        key = self.credentials.get("api_key")
        client = ClientFactory.get_client(key, api_version='v0.4', print_json=True)
        obj_type = self.request.type.short_name
        if obj_type.lower() in ["sha256"]:
            self.vendor_response = client.search_hash(sha256=self.request.value)
            with open("/app/scarlet_shark_hash.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["domain"]:
            self.vendor_response = client.search_domain(self.request.value)
            with open("/app/scarlet_shark_domain.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["ipv4", "ipv6"]:
            obj = client.search_ip(ip=self.request.value).get('ips', [])
            if obj:
                obj = obj[0]
            self.vendor_response = obj
            with open("/app/scarlet_shark_ip.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["url"]:
            obj = client.search_url(url=self.request.value).get('urls', [])
            if obj:
                obj = obj[0]
            self.vendor_response = obj
            with open("/app/scarlet_shark_url.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["email"]:
            obj = client.search_email(email=self.request.value)
            if obj:
                obj = obj[0]
            self.vendor_response = obj
            with open("/app/scarlet_shark_email.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        return self.vendor_response

    def save_results(self):
        pass

    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        return self.entities, self.relations, self.events
