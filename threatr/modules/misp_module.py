import logging

from colander_data_converter.base.models import CommonEntitySuperTypes
from colander_data_converter.base.types.observable import ObservableTypes
from colander_data_converter.converters.misp.converter import MISPToColanderMapper
from colander_data_converter.converters.misp.models import Mapping, EntityTypeMapping
from colander_data_converter.converters.threatr.converter import ColanderToThreatrMapper
from pymisp import PyMISP, MISPAttribute

from threatr.core.models import (
    Request, Entity, EntityRelation, Event, EntitySuperType, EntityType,
)
from threatr.modules.module import AnalysisModule, ModuleUtils

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
        self.in_error = False

    @classmethod
    def unique_identifier(cls) -> str:
        return "misp"

    @classmethod
    def vendor(cls) -> str:
        return "MISP"

    @classmethod
    def description(cls) -> str:
        return "Get intelligence from MISP."

    @classmethod
    def supported_types(cls) -> dict[str, list[str]]:
        return {
            'observable': ['ipv4', 'ipv6', 'domain', 'md5', 'sha1', 'sha256', 'email'],
        }

    def fail_fast(self) -> bool:
        return super().fail_fast()

    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        return self.entities, self.relations, self.events

    def save_results(self):
        if self.in_error:
            return
        misp_attribute = MISPAttribute()
        misp_attribute.from_dict(**self.vendor_response)
        converter = MISPToColanderMapper()
        colander_entity = converter.convert_attribute(misp_attribute)
        threatr_mapper = ColanderToThreatrMapper()
        threatr_entity = threatr_mapper.convert_entity(colander_entity)
        entity, _ = Entity.objects.update_or_create(
            name=threatr_entity.name,
            super_type=EntitySuperType.get_types().get("OBSERVABLE"),
            type=EntityType.get_types("OBSERVABLE").get(threatr_entity.type.short_name),
            defaults={
                "description": threatr_entity.description,
                "tlp": threatr_entity.tlp,
                "pap": threatr_entity.pap,
            }
        )
        if threatr_entity.attributes:
            tags = threatr_entity.attributes.get("tags", "")
            ModuleUtils.merge_tags(entity, tags)
        entity.save()
        self.entities.append(entity)

    def execute_request(self):
        misp_url = self.credentials.get("url")
        misp_key = self.credentials.get("api_key")
        mapping = Mapping()
        requested_value = self.request.value
        requested_type = self.request.type
        entity_type = ObservableTypes.by_short_name(requested_type.short_name)
        entity_type_mapping: EntityTypeMapping = mapping.get_mapping_to_misp(
            CommonEntitySuperTypes.OBSERVABLE.value,
            entity_type
        )
        misp_type = entity_type_mapping.misp_type
        try:
            pymisp = PyMISP(misp_url, misp_key, debug=False)
            self.vendor_response = pymisp.search(
                controller="attributes",
                type=misp_type,
                value=requested_value,
                return_json=True,
                limit=1,
                published=True,
                to_ids=True,
                include_event_tags=True
            )
        except (Exception, ):
            self.in_error = True
            return None
        if not isinstance(self.vendor_response, dict) or len(self.vendor_response.get("Attribute", [])) != 1:
            self.in_error = True
            return None
        self.vendor_response["Attribute"] = self.vendor_response.get("Attribute", [])[0]
        return self.vendor_response
