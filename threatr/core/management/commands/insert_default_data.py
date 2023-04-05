import json

import pkg_resources
from django.core.management.base import BaseCommand

from threatr.core.models import EntitySuperType, EntityType


class Command(BaseCommand):
    help = "Insert default data."

    def handle(self, *args, **options):
        definitions = "data/entity_types.json"

        resource_package = __name__
        types_file = pkg_resources.resource_stream(resource_package, definitions)
        entity_types = json.load(types_file)

        for super_type in entity_types:
            super_type_obj, _ = EntitySuperType.objects.update_or_create(
                short_name=super_type.get("short_name"),
                defaults={
                    "name": super_type.get("name"),
                    "nf_icon": super_type.get("nf_icon"),
                },
            )
            for entity_type in super_type.get("types"):
                EntityType.objects.update_or_create(
                    short_name=entity_type.get("short_name"),
                    super_type=super_type_obj,
                    defaults={
                        "name": entity_type.get("name"),
                        "nf_icon": entity_type.get("nf_icon"),
                    },
                )
