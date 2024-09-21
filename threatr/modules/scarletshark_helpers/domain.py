from typing import Optional

from scarlet_shark_client.client import ClientFactory

from threatr.core.models import Entity, EntitySuperType, EntityType


class Domain:
    def __init__(self, domain_name: str, client: ClientFactory):
        self.domain_name = domain_name
        self.client = client

    @staticmethod
    def create_entity(domain_data: dict, vendor: str = 'ScarletShark') -> Optional[Entity]:
        domain_name = domain_data.get('domain', None)
        if not domain_name:
            return None
        domain, created = Entity.objects.update_or_create(
            name=domain_name,
            super_type=EntitySuperType.get_types().get("OBSERVABLE"),
            type=EntityType.get_types("OBSERVABLE").get("DOMAIN"),
            defaults={
                "description": domain_data.get('domain_description', ''),
            }
        )
        if created:
            domain.attributes = {"source_vendor": vendor}
        # Source URL
        if not domain.source_url and domain_data.get('reference_url', None):
            domain.source_url = domain_data.get('reference_url')
        # Age of the domain registration
        domain_age = domain_data.get('age', -1)
        if domain_age > -1:
            domain.attributes['age'] = domain_age
        registration_date = domain_data.get('registered', None)
        if registration_date:
            domain.attributes.setdefault('registration_date', registration_date)
        domain.save()
        return None

    def search(self):
        return None
