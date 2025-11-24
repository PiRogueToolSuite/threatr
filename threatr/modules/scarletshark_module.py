import json
import logging
from scarlet_shark_client.client import ClientFactory

from threatr.core.models import (
    Entity,
    EntityRelation,
    Request,
    Event, EntitySuperType, EntityType,
)
from threatr.modules.module import AnalysisModule, ModuleUtils

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
        key = self.credentials.get('api_key', '')
        self.client = ClientFactory.get_client(key, api_version='v0.4', print_json=False)

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
            'observable': ['domain'],
            'actor': ['threat_actor']
        }

    def fail_fast(self) -> bool:
        return super().fail_fast()

    def execute_request(self) -> dict:
        obj_type = self.request.type.short_name
        if obj_type.lower() in ["sha256"]:
            self.vendor_response = self.client.search_hash(sha256=self.request.value)
            with open("/app/scarlet_shark_hash.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["domain"]:
            self.vendor_response = self.client.search_domain(self.request.value)
            with open("/app/scarlet_shark_domain.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["ipv4", "ipv6"]:
            obj = self.client.search_ip(ip=self.request.value).get('ips', [])
            if obj:
                obj = obj[0]
            self.vendor_response = obj
            with open("/app/scarlet_shark_ip.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["url"]:
            obj = self.client.search_url(url=self.request.value).get('urls', [])
            if obj:
                obj = obj[0]
            self.vendor_response = obj
            with open("/app/scarlet_shark_url.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif obj_type.lower() in ["email"]:
            obj = self.client.search_email(email=self.request.value)
            if obj:
                obj = obj[0]
            self.vendor_response = obj
            with open("/app/scarlet_shark_email.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        return self.vendor_response

    def __process_threat_actor(self, actor_id):
        if actor_id < 1: return None  # noqa: E701
        result = self.client.search_threat_actors(threat_actor_id=actor_id)
        if not result: return None  # noqa: E701
        aliases = result.get('aliases', [])
        if not aliases: return None  # noqa: E701
        name = aliases.pop(0).get('alias_name')
        description = result.get('description', '')
        actor, _ = Entity.objects.update_or_create(
            name=name.strip(),
            super_type=EntitySuperType.get_types().get("ACTOR"),
            type=EntityType.get_types("ACTOR").get("THREAT_ACTOR"),
        )
        ModuleUtils.merge_attributes(actor, {
            'source_vendor': self.vendor(),
        })
        if not actor.description and description:
            actor.description = description
        actor.save()
        for alias in aliases:
            alias_name = alias.get('alias_name', '')
            if not alias_name: continue  # noqa: E701
            a, _ = Entity.objects.update_or_create(
                name=alias_name.strip(),
                super_type=EntitySuperType.get_types().get("ACTOR"),
                type=EntityType.get_types("ACTOR").get("THREAT_ACTOR"),
            )
            ModuleUtils.merge_attributes(a, {
                'source_vendor': self.vendor(),
            })
            aka, _ = EntityRelation.objects.update_or_create(
                name="also known as",
                obj_from=actor,
                obj_to=a,
            )
        return actor

    def __process_domain(self):
        if not self.vendor_response.get('domain', ''):
            return None
        domain = self.vendor_response.get('domain', '')
        registration_date = self.vendor_response.get('registered', '')
        reference_url = self.vendor_response.get('reference_url', '')
        domain_description = self.vendor_response.get('domain_description', '')
        tags = self.vendor_response.get('tags', [])
        d, _ = Entity.objects.update_or_create(
            name=domain.strip(),
            super_type=EntitySuperType.get_types().get("OBSERVABLE"),
            type=EntityType.get_types("OBSERVABLE").get("DOMAIN"),
        )
        ModuleUtils.merge_attributes(d, {
            'source_vendor': self.vendor(),
            'registration_date': registration_date,
            'reference_url': reference_url
        })
        ModuleUtils.merge_tags(d, tags)
        if not d.description and domain_description:
            d.description = domain_description
        threat_actor_id = self.vendor_response.get('threat_actor_id', 0)
        threat_actor = self.__process_threat_actor(threat_actor_id)
        if threat_actor:
            d.attributes['is_malicious'] = True
            d.attributes['operated_by'] = str(threat_actor.id)
            relation, created = EntityRelation.objects.update_or_create(
                name="operated by", obj_from=d, obj_to=threat_actor
            )
            if created:
                relation.attributes = {"source_vendor": self.vendor()}
                relation.save()
        d.save()
        return d

    def save_results(self):
        # Create or update root entity
        root, created = Entity.objects.update_or_create(
            name=self.request.value,
            super_type=self.request.super_type,
            type=self.request.type,
        )
        ModuleUtils.merge_attributes(root, {
            'source_vendor': self.vendor(),
        })
        root.save()
        if self.request.type.short_name.lower() == 'domain':
            self.__process_domain()

    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        return self.entities, self.relations, self.events
