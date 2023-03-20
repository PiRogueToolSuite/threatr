import json
import logging
import pytz
from OTXv2 import IndicatorTypes, OTXv2
from dateutil.parser import parse

from threatr.core.models import Entity, EntityRelation, Request, EntitySuperType, EntityType, Event
from threatr.modules.module import AnalysisModule

OTX_TYPES_MAPPING = {
    "DOMAIN": IndicatorTypes.DOMAIN,
    "IPV4": IndicatorTypes.IPv4,
    "IPV6": IndicatorTypes.IPv6,
    "URL": IndicatorTypes.URL,
    "MD5": IndicatorTypes.FILE_HASH_MD5,
    "SHA1": IndicatorTypes.FILE_HASH_SHA1,
    "SHA256": IndicatorTypes.FILE_HASH_SHA256,
    "PEHASH": IndicatorTypes.FILE_HASH_PEHASH,
    "IMPHASH": IndicatorTypes.FILE_HASH_IMPHASH,
    "CIDR": IndicatorTypes.CIDR,
    "PATH": IndicatorTypes.FILE_PATH,
    "HOSTNAME": IndicatorTypes.HOSTNAME,
    "MUTEX": IndicatorTypes.MUTEX,
    "CVE": IndicatorTypes.CVE
}

logger = logging.getLogger(__name__)

class OTX(AnalysisModule):
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
        return 'otx'

    @classmethod
    def vendor(cls) -> str:
        return 'OTX Alien Vault'

    @classmethod
    def description(cls) -> str:
        return "Get intelligence from OTX Alien Vault."

    @classmethod
    def handled_super_types(cls) -> [str]:
        return ['observable']

    @classmethod
    def handled_types(cls) -> [str]:
        return ['ipv4','ipv6','domain','sha256']

    def fail_fast(self) -> bool:
        if 'api_key' not in self.credentials:
            logger.error('Not API key provided')
            return True
        if self.request.super_type.short_name.lower() not in self.handled_super_types():
            logger.error(f'This module cannot handle the requested super-type [{self.request.super_type.short_name}]')
            return True
        if self.request.type.short_name.lower() not in self.handled_types():
            logger.error(f'This module cannot handle the requested type [{self.request.type.short_name}]')
            return True
        return False

    def execute_request(self) -> dict:
        key = self.credentials.get('api_key')
        otx = OTXv2(key)
        otx_type = OTX_TYPES_MAPPING.get(self.request.type.short_name)
        self.vendor_response = otx.get_indicator_details_full(otx_type, self.request.value)
        with open(f'/app/otx_{otx_type}.json', mode='w') as out:
            json.dump(self.vendor_response, out)
        # with open('/app/otx_sha256.json', mode='r') as out:
        #     self.vendor_response = json.load(out)
        return self.vendor_response

    def save_results(self):
        entities = []
        relations = []
        events = []

        # Create or update root entity
        root, created = Entity.objects.update_or_create(
            name = self.request.value,
            super_type = self.request.super_type,
            type = self.request.type,
        )
        if created:
            root.attributes = {'source_vendor': self.vendor()}
            root.save()

        entities.append(root)

        if 'url_list' in self.vendor_response:
            for r in self.vendor_response["url_list"]["url_list"]:
                if "result" in r:
                    url, created = Entity.objects.update_or_create(
                        name = r["url"].strip(),
                        super_type = EntitySuperType.get_types().get('OBSERVABLE'),
                        type = EntityType.get_types('OBSERVABLE').get('URL'),
                    )
                    if created:
                        url.attributes = {'source_vendor': self.vendor()}
                        url.save()
                    entities.append(url)

                    relation, created = EntityRelation.objects.update_or_create(
                        name = 'serves',
                        obj_from = root,
                        obj_to = url,
                    )
                    if created:
                        relation.attributes = {'source_vendor': self.vendor()}
                        relation.save()
                    if 'seen_at' not in relation.attributes:
                        relation.attributes['seen_at'] = parse(r["date"]).astimezone(pytz.utc)
                        relation.save()
                    relations.append(relation)

        if 'passive_dns' in self.vendor_response:
            for r in self.vendor_response["passive_dns"]["passive_dns"]:
                record_type = r.get('record_type').strip()
                address = r.get('address').strip()
                event, created = Event.objects.update_or_create(
                    name = f'{record_type} {address}',
                    type = EntityType.get_types('EVENT').get('PASSIVE_DNS'),
                    first_seen = parse(r["first"]).astimezone(pytz.utc),
                    last_seen = parse(r["last"]).astimezone(pytz.utc),
                    involved_entity=root,
                    defaults={
                        'count':1,
                        'attributes':{'source_vendor': self.vendor()}
                    }
                )
                if created:
                    event.attributes = {'source_vendor': self.vendor(), 'count': 1}
                    event.save()
                if 'asn' not in event.attributes:
                    event.attributes['asn'] = r.get('asn', '')
                    event.save()
                events.append(event)

        if 'pulse_info' in self.vendor_response.get('general') and self.vendor_response.get('general').get('pulse_info').get('count', 0) > 0:
            for r in self.vendor_response.get('general').get('pulse_info').get('pulses'):
                references = r.get('references')
                source_url = ''
                if len(references) > 0:
                    source_url = references[0]
                if source_url:
                    doc, created = Entity.objects.update_or_create(
                        name = r.get('name'),
                        super_type = EntitySuperType.get_types().get('EXT_DOC'),
                        type = EntityType.get_types('EXT_DOC').get('REPORT'),
                        defaults={
                            'source_url': source_url,
                            'description': r.get('description', '')
                        }
                    )
                    if created:
                        doc.attributes = {'source_vendor': self.vendor()}
                    elif r.get('description', '').strip() and not doc.description:
                        doc.description = r.get('description').strip()
                    doc.save()

                    if 'tags' not in doc.attributes and r.get('tags', ''):
                        doc.attributes['tags'] = ','.join(r.get('tags'))
                    if 'modified' not in doc.attributes and 'created' not in doc.attributes:
                        doc.attributes['modified'] = parse(r["modified"]).astimezone(pytz.utc)
                        doc.attributes['created'] = parse(r["created"]).astimezone(pytz.utc)
                    doc.save()
                    entities.append(doc)
                    relation, _ = EntityRelation.objects.update_or_create(
                        name = 'documents',
                        obj_from = doc,
                        obj_to = root,
                        defaults={'attributes':{'source_vendor': self.vendor()}}
                    )
                    relations.append(relation)

        if 'analysis' in self.vendor_response and 'analysis' in self.vendor_response.get('analysis'):
            analysis = self.vendor_response.get('analysis').get('analysis')
            if analysis:
                analysis_date = parse(analysis["datetime_int"]).astimezone(pytz.utc)
                if 'info' in analysis and 'results' in analysis.get('info'):
                    for k, v in analysis.get('info').get('results').items():
                        if k.upper() != root.type and k not in root.attributes:
                            if type(v) not in [list, dict]:
                                root.attributes[k] = v
                    root.save()
            if 'plugins' in analysis:
                for vendor, elt in analysis.get('plugins').items():
                    if vendor == 'cuckoo' and 'behavior' in elt.get('result'):
                        behavior = elt.get('result').get('behavior')
                        if 'connects_ip' in behavior:
                            for ip in behavior.get('connects_ip'):
                                ip_type = EntityType.get_types('OBSERVABLE').get('IPV4')
                                if ':' in ip:
                                    ip_type = EntityType.get_types('OBSERVABLE').get('IPV6')
                                ip_obj, created = Entity.objects.update_or_create(
                                    name = ip,
                                    super_type = EntitySuperType.get_types().get('OBSERVABLE'),
                                    type = ip_type,
                                )
                                if created:
                                    ip_obj.attributes = {'source_vendor': self.vendor()}
                                    ip_obj.save()
                                entities.append(ip_obj)
                                ip_rel, created = EntityRelation.objects.update_or_create(
                                    name = 'connects to',
                                    obj_from = root,
                                    obj_to = ip_obj,
                                )
                                if created:
                                    ip_rel.attributes = {'source_vendor': self.vendor()}
                                    ip_rel.save()
                                relations.append(ip_rel)
                    if 'results' not in elt:
                        continue
                    results = elt.get('results')
                    if results and vendor == 'exiftool':
                        for k, v in results.items():
                            if k not in root.attributes and type(v) not in [list, dict]:
                                root.attributes[k] = v
                        root.save()
                    if results and 'detection' in results and 'alerts' in results:
                        event, _ = Event.objects.update_or_create(
                            name = results.get('detection'),
                            type = EntityType.get_types('EVENT').get('AV_DETECTION'),
                            first_seen = analysis_date,
                            last_seen = analysis_date,
                            involved_entity = root,
                            defaults={
                                'description': ', '.join(results.get('alerts')),
                                'attributes':{'source_vendor': self.vendor()},
                                'count': 1,
                            }
                        )
                        event.save()
                        events.append(event)
        self.entities = list(set(entities))
        self.relations = list(set(relations))
        self.events = list(set(events))

    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        return self.entities, self.relations, self.events


