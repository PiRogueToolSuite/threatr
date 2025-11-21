import logging
from typing import Tuple, List

from colander_data_converter.base.models import CommonEntitySuperTypes
from colander_data_converter.base.types.actor import ActorTypes as cdc_ActorTypes
from colander_data_converter.base.types.artifact import ArtifactTypes as cdc_ArtifactTypes
from colander_data_converter.base.types.base import CommonEntityType as cdc_CommonEntityType
from colander_data_converter.base.types.data_fragment import DataFragmentTypes as cdc_DataFragmentTypes
from colander_data_converter.base.types.detection_rule import DetectionRuleTypes as cdc_DetectionRuleTypes
from colander_data_converter.base.types.device import DeviceTypes as cdc_DeviceTypes
from colander_data_converter.base.types.event import EventTypes as cdc_EventTypes
from colander_data_converter.base.types.observable import ObservableTypes as cdc_ObservableTypes
from colander_data_converter.base.types.threat import ThreatTypes as cdc_ThreatTypes
from django.core.management.base import BaseCommand
from django.db import IntegrityError

from threatr.core.models import EntitySuperType, EntityType

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Insert default data."

    def handle(self, *args, **options):
        """
        Inserts default data into the database for each entity type defined in the system.

        Iterates over a list of model types and their corresponding enum definitions,
        and for each enum value, updates or creates a database entry with the default attributes.

        Side Effects:
            Updates or creates records in the database for each entity type.
        """

        definitions: List[Tuple] = [
            (CommonEntitySuperTypes.ACTOR.value, cdc_ArtifactTypes),
            (CommonEntitySuperTypes.OBSERVABLE.value, cdc_ObservableTypes),
            (CommonEntitySuperTypes.THREAT.value, cdc_ThreatTypes),
            (CommonEntitySuperTypes.ACTOR.value, cdc_ActorTypes),
            (CommonEntitySuperTypes.EVENT.value, cdc_EventTypes),
            (CommonEntitySuperTypes.DEVICE.value, cdc_DeviceTypes),
            (CommonEntitySuperTypes.DETECTION_RULE.value, cdc_DetectionRuleTypes),
            (CommonEntitySuperTypes.DATA_FRAGMENT.value, cdc_DataFragmentTypes),
        ]

        # Extra types
        super_type_obj, _ = EntitySuperType.objects.update_or_create(
            short_name="TTP", defaults={"name": "TTP"},
        )
        EntityType.objects.update_or_create(
            short_name="MITRE", super_type=super_type_obj,
            defaults={'name': "MITRE ATT&CK.", 'nf_icon': "nf-fa-bug"}
        )
        super_type_obj, _ = EntitySuperType.objects.update_or_create(
            short_name="EXT_DOC", defaults={"name": "External documentation"},
        )
        EntityType.objects.update_or_create(
            short_name="REPORT", super_type=super_type_obj,
            defaults={'name': "Analysis report", 'nf_icon': "nf-fa-file-lines"}
        )
        EntityType.objects.update_or_create(
            short_name="AUTO_ANALYSIS", super_type=super_type_obj,
            defaults={'name': "Automatic analysis", 'nf_icon': "nf-fa-file-lines"}
        )

        for entity_type, type_definitions in definitions:
            super_type_obj, _ = EntitySuperType.objects.update_or_create(
                short_name=entity_type.short_name,
                defaults={
                    "name": entity_type.name,
                },
            )
            for obj_type in type_definitions:
                obj_type_definition: cdc_CommonEntityType = obj_type.value
                try:
                    EntityType.objects.update_or_create(
                        short_name=obj_type_definition.short_name,
                        super_type=super_type_obj,
                        defaults={
                            'name': obj_type_definition.name,
                            'description': obj_type_definition.description,
                            'nf_icon': obj_type_definition.nf_icon,
                        }
                    )
                except (IntegrityError, Exception) as e:
                    logger.error(e)
