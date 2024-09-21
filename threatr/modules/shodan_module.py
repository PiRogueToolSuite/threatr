import json
import logging

from shodan import Shodan, APIError

from threatr.core.models import (
    Entity,
    EntityRelation,
    Request,
    Event, EntitySuperType, EntityType,
)
from threatr.modules.module import AnalysisModule, ModuleUtils

logger = logging.getLogger(__name__)


class ShodanModule(AnalysisModule):
    """
    IP -> device (server) -> service / actor / location / cve
       -> domain
    To list the services, pivot on the device
    """

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

    def execute_request(self):
        key = self.credentials.get("api_key")
        shodan_api: Shodan = Shodan(key)
        try:
            self.vendor_response = shodan_api.host(self.request.value)
        except APIError as e:
            logger.exception(e)
            self.vendor_response = {}
        with open("/app/shodan.json", mode="w") as out:
            json.dump(self.vendor_response, out)
        return self.vendor_response

    def __process_ip(self) -> Entity:
        # Create or update root entity
        root, created = Entity.objects.update_or_create(
            name=self.request.value,
            super_type=self.request.super_type,
            type=self.request.type,
        )
        ModuleUtils.merge_attributes(root, {
            'source_vendor': self.vendor(),
            'shodan_scan_date': self.vendor_response.get('last_update'),
            'asn': self.vendor_response.get('asn', ''),
            'isp': self.vendor_response.get('isp', ''),
            'organization': self.vendor_response.get('org', ''),
        })
        root.save()
        return root

    def __process_domains(self, root_entity: Entity) -> (list[Entity], list[EntityRelation]):
        domains = []
        relations = []
        for domain in self.vendor_response.get('domains'):
            d, _ = Entity.objects.update_or_create(
                name=domain.strip(),
                super_type=EntitySuperType.get_types().get("OBSERVABLE"),
                type=EntityType.get_types("OBSERVABLE").get("DOMAIN"),
            )
            ModuleUtils.merge_attributes(d, {
                'source_vendor': self.vendor(),
                'shodan_scan_date': self.vendor_response.get('last_update'),
            })
            d.save()
            domains.append(d)
            relation, _ = EntityRelation.objects.update_or_create(
                name="resolves to",
                obj_from=d,
                obj_to=root_entity,
            )
            relations.append(relation)
        return domains, relations

    def __process_cves(self, server: Entity) -> (list[Entity], list[EntityRelation]):
        cves = []
        relations = []
        for cve in self.vendor_response.get('vulns', []):
            c, _ = Entity.objects.update_or_create(
                name=cve.strip(),
                super_type=EntitySuperType.get_types().get("OBSERVABLE"),
                type=EntityType.get_types("OBSERVABLE").get("CVE"),
            )
            summary = ''
            cvss_v2 = ''
            if type(cve) is dict:
                summary = cve.get('summary', '').strip()
                cvss_v2 = cve.get('cvss_v2', '')
            ModuleUtils.merge_attributes(c, {
                'source_vendor': self.vendor(),
                'shodan_scan_date': self.vendor_response.get('last_update'),
                'cvss_v2': cvss_v2
            })
            if summary:
                c.description = summary
            c.save()
            cves.append(c)
            relation, _ = EntityRelation.objects.update_or_create(
                name="affects",
                obj_from=c,
                obj_to=server,
            )
            relations.append(relation)
        return cves, relations

    def __process_server_location(self, server: Entity) -> (list[Entity], list[EntityRelation]):
        entities = []
        relations = []
        country = self.vendor_response.get('country_name', '')
        city = self.vendor_response.get('city', '')
        location_info = []
        if country: location_info.append(country)  # noqa: E701
        if city: location_info.append(city)  # noqa: E701
        if not location_info: location_info.append('Server location')  # noqa: E701
        l, _ = Entity.objects.update_or_create(
            name=' - '.join(location_info),
            super_type=EntitySuperType.get_types().get("OBSERVABLE"),
            type=EntityType.get_types("OBSERVABLE").get("LOCATION"),
        )
        ModuleUtils.merge_attributes(l, {
            'source_vendor': self.vendor(),
            'shodan_scan_date': self.vendor_response.get('last_update'),
            'latitude': self.vendor_response.get('latitude', ''),
            'longitude': self.vendor_response.get('longitude', ''),
            'city': self.vendor_response.get('city', ''),
            'country_name': self.vendor_response.get('country_name', ''),
            'country_code': self.vendor_response.get('country_code', ''),
        })
        l.save()
        entities.append(l)
        relation, _ = EntityRelation.objects.update_or_create(
            name="located at",
            obj_from=server,
            obj_to=l,
        )
        relations.append(relation)
        return entities, relations

    def __process_services(self, server: Entity) -> (list[Entity], list[EntityRelation]):
        entities = []
        relations = []
        for service in self.vendor_response.get('data', []):
            service_name = 'Service'
            service_product = service.get('product', '')
            service_protocol = ''
            if '_shodan' in service:
                service_protocol = service.get('_shodan').get('module').split('-')[0].upper()
            service_port = service.get('port', '')
            service_transport = service.get('transport', '')
            if service_protocol: service_name = f'{service_protocol} service'  # noqa: E701
            if service_product: service_name += f' {service_product}'  # noqa: E701
            if service_port: service_name += f' listening on port {service_port}'  # noqa: E701
            if service_transport: service_name += f' [{service_transport.upper()}]'  # noqa: E701
            s, _ = Entity.objects.update_or_create(
                name=service_name,
                super_type=EntitySuperType.get_types().get("OBSERVABLE"),
                type=EntityType.get_types("OBSERVABLE").get("SERVICE"),
            )
            ModuleUtils.merge_attributes(s, {
                'source_vendor': self.vendor(),
                'protocol': service_protocol,
                'product': service_product,
                'port': service_port,
                'transport': service_transport,
                'shodan_scan_date': service.get('timestamp'),
                'use_ssl': 'ssl' in service,
            })
            s.save()
            entities.append(s)
            relation, _ = EntityRelation.objects.update_or_create(
                name="exposes",
                obj_from=server,
                obj_to=s,
            )
            relations.append(relation)
        return entities, relations

    def __process_server(self, root_entity: Entity) -> Entity:
        server_name = f'Server @{root_entity.name}'
        hostnames = self.vendor_response.get('hostnames', []).copy()
        server_shorter_hostname, _ = ModuleUtils.get_shorter_entry(hostnames)
        if server_shorter_hostname: server_name = server_shorter_hostname  # noqa: E701
        s, _ = Entity.objects.update_or_create(
            name=server_name,
            super_type=EntitySuperType.get_types().get("DEVICE"),
            type=EntityType.get_types("DEVICE").get("SERVER"),
        )
        ModuleUtils.merge_attributes(s, {
            'source_vendor': self.vendor(),
            'shodan_scan_date': self.vendor_response.get('last_update'),
        })
        ModuleUtils.merge_tags(s, self.vendor_response.get('tags', []))
        s.save()
        relation, _ = EntityRelation.objects.update_or_create(
            name="assigned to",
            obj_from=root_entity,
            obj_to=s,
        )
        for hostname in self.vendor_response.get('hostnames', []):
            h, _ = Entity.objects.update_or_create(
                name=hostname.strip(),
                super_type=EntitySuperType.get_types().get("OBSERVABLE"),
                type=EntityType.get_types("OBSERVABLE").get("HOSTNAME"),
            )
            ModuleUtils.merge_attributes(s, {
                'source_vendor': self.vendor(),
                'shodan_scan_date': self.vendor_response.get('last_update'),
            })
            EntityRelation.objects.update_or_create(
                name="maps to",
                obj_from=h,
                obj_to=s,
            )
        return s

    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        pass

    def save_results(self):
        root_entity = self.__process_ip()
        self.__process_domains(root_entity)
        server = self.__process_server(root_entity)
        self.__process_services(server)
        self.__process_cves(server)
        self.__process_server_location(server)
