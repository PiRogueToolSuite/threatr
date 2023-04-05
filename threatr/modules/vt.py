import json
import logging
from datetime import datetime

import pytz
from vt import Client

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


def _get_vt_score(response):
    total = 0
    malicious = 0
    for cat, v in response["last_analysis_stats"].items():
        total += v
        if cat == "malicious":
            malicious += v
    return malicious, total


def _get_vt_threat_cat_and_name(response):
    cat = ""
    name = ""
    threat_type = EntityType.get_types("THREAT").get("GENERIC")
    if (
        "popular_threat_classification" in response
        and response["popular_threat_classification"]
    ):
        classification = response["popular_threat_classification"]
        if classification["suggested_threat_label"]:
            name = classification["suggested_threat_label"]
        else:
            name = "/".join([e["value"] for e in classification["popular_threat_name"]])
        if classification["popular_threat_category"]:
            cat = "/".join(
                [e["value"] for e in classification["popular_threat_category"]]
            )
        if "/" not in cat and cat.upper() in EntityType.get_types("THREAT"):
            threat_type = EntityType.get_types("THREAT").get(cat.upper())
    return cat, name, threat_type


class VirusTotal(AnalysisModule):
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
        return "vt"

    @classmethod
    def vendor(cls) -> str:
        return "VirusTotal"

    @classmethod
    def description(cls) -> str:
        return "Get intelligence from VirusTotal."

    @classmethod
    def handled_super_types(cls) -> [str]:
        return ["observable"]

    @classmethod
    def handled_types(cls) -> [str]:
        return ["ipv4", "ipv6", "domain", "sha256", "sha1", "md5", "url"]

    def fail_fast(self) -> bool:
        if "api_key" not in self.credentials:
            logger.error("Not API key provided")
            return True
        if self.request.super_type.short_name.lower() not in self.handled_super_types():
            logger.error(
                f"This module cannot handle the requested super-type [{self.request.super_type.short_name}]"
            )
            return True
        if self.request.type.short_name.lower() not in self.handled_types():
            logger.error(
                f"This module cannot handle the requested type [{self.request.type.short_name}]"
            )
            return True
        return False

    def execute_request(self) -> dict:
        key = self.credentials.get("api_key")
        vt = Client(key)
        if self.request.type.short_name.lower() in ["sha256", "sha1", "md5"]:
            self.vendor_response = vt.get_json(f"/files/{self.request.value}")
            with open("/app/vt_hash.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif self.request.type.short_name.lower() in ["domain"]:
            self.vendor_response = vt.get_json(f"/domains/{self.request.value}")
            with open("/app/vt_domain.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif self.request.type.short_name.lower() in ["ipv4", "ipv6"]:
            self.vendor_response = vt.get_json(f"/ip_addresses/{self.request.value}")
            with open("/app/vt_ip.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        elif self.request.type.short_name.lower() in ["url"]:
            self.vendor_response = vt.get_json(f"/urls/{self.request.value}")
            with open("/app/vt_url.json", mode="w") as out:
                json.dump(self.vendor_response, out)
        return self.vendor_response

    def save_results(self):
        entities = []
        relations = []
        events = []

        response = self.vendor_response["data"]["attributes"]

        root, created = Entity.objects.update_or_create(
            name=self.request.value,
            super_type=self.request.super_type,
            type=self.request.type,
        )
        if created:
            root.attributes = {"source_vendor": self.vendor()}
            root.save()

        if "tlsh" in response:
            root.attributes["tlsh"] = response["tlsh"]
        if "vhash" in response:
            root.attributes["vhash"] = response["vhash"]
        if "size" in response:
            root.attributes["size"] = response["size"]
        if "sha1" in response:
            root.attributes["sha1"] = response["sha1"]
        if "ssdeep" in response:
            root.attributes["ssdeep"] = response["ssdeep"]
        if "md5" in response:
            root.attributes["md5"] = response["md5"]
        if "country" in response:
            root.attributes["geoip_country"] = response["country"]
        if "continent" in response:
            root.attributes["geoip_continent"] = response["continent"]
        if "as_owner" in response:
            root.attributes["operator"] = response["as_owner"]
        malicious, total = _get_vt_score(response)
        if malicious > 0:
            root.attributes["is_malicious"] = 1
        else:
            root.attributes["is_malicious"] = 0
        root.attributes["vt_score"] = f"{malicious}/{total}"
        if "categories" in response and "alphaMountain.ai" in response["categories"]:
            root.attributes["category"] = response["categories"]["alphaMountain.ai"]
        root.save()

        if malicious > 0:
            cat, name, threat_type = _get_vt_threat_cat_and_name(response)
            if name:
                threat, created = Entity.objects.update_or_create(
                    name=name if name else "Uncategorized",
                    super_type=EntitySuperType.get_types().get("THREAT"),
                    type=threat_type,
                )
                if created:
                    threat.attributes = {"source_vendor": self.vendor()}
                    threat.save()
                if response["tags"] and "tags" not in threat.attributes:
                    threat.attributes["tags"] = ",".join(response["tags"])
                    threat.save()
                root.attributes["associated_threat"] = str(threat.id)
                entities.append(threat)

                relation, created = EntityRelation.objects.update_or_create(
                    name="associated threat",
                    obj_from=root,
                    obj_to=threat,
                )
                if created:
                    relation.attributes = {"source_vendor": self.vendor()}
                    relation.save()
                relations.append(relation)

        if "last_dns_records" in response and response["last_dns_records"]:
            for record in response["last_dns_records"]:
                t = record["type"]
                v = record["value"]
                dns_record, created = Entity.objects.update_or_create(
                    name=f"{t} {v}",
                    super_type=EntitySuperType.get_types().get("OBSERVABLE"),
                    type=EntityType.get_types("OBSERVABLE").get("DNS_RECORD"),
                )
                if created:
                    dns_record.attributes = {"source_vendor": self.vendor()}
                    dns_record.save()

                if t in ["A", "AAAA"]:
                    ip_type = EntityType.get_types("OBSERVABLE").get("IPV4")
                    if t == "AAAA":
                        ip_type = EntityType.get_types("OBSERVABLE").get("IPV6")
                    target_ip, created = Entity.objects.update_or_create(
                        name=v,
                        super_type=EntitySuperType.get_types().get("OBSERVABLE"),
                        type=ip_type,
                    )
                    if created:
                        target_ip.attributes = {"source_vendor": self.vendor()}
                        target_ip.save()
                    entities.append(target_ip)
                    record_to_ip, created = EntityRelation.objects.update_or_create(
                        name="points to", obj_from=dns_record, obj_to=target_ip
                    )
                    if created:
                        record_to_ip.attributes = {"source_vendor": self.vendor()}
                        record_to_ip.save()
                    relations.append(record_to_ip)
                    ip_to_domain, created = EntityRelation.objects.update_or_create(
                        name="resolves", obj_from=target_ip, obj_to=root
                    )
                    if created:
                        ip_to_domain.attributes = {"source_vendor": self.vendor()}
                        ip_to_domain.save()
                    relations.append(ip_to_domain)
                else:
                    relation, created = EntityRelation.objects.update_or_create(
                        name="resolves", obj_from=dns_record, obj_to=root
                    )
                    if created:
                        relation.attributes = {"source_vendor": self.vendor()}
                        relation.save()
                    relations.append(relation)

        if "first_submission_date" in response and "last_submission_date" in response:
            av_submissions, _ = Event.objects.update_or_create(
                name="Submission on VT",
                type=EntityType.get_types("EVENT").get("HIT"),
                first_seen=datetime.fromtimestamp(
                    response["first_submission_date"]
                ).astimezone(pytz.utc),
                last_seen=datetime.fromtimestamp(
                    response["last_submission_date"]
                ).astimezone(pytz.utc),
                involved_entity=root,
                defaults={
                    "count": response["times_submitted"],
                    "attributes": {"source_vendor": self.vendor()},
                },
            )
            events.append(av_submissions)
        if malicious > 0:
            av_analysis, _ = Event.objects.update_or_create(
                name="Analysis on VT",
                type=EntityType.get_types("EVENT").get("AV_DETECTION"),
                first_seen=datetime.fromtimestamp(
                    response["last_analysis_date"]
                ).astimezone(pytz.utc),
                last_seen=datetime.fromtimestamp(
                    response["last_analysis_date"]
                ).astimezone(pytz.utc),
                involved_entity=root,
                defaults={"count": 1, "attributes": {"source_vendor": self.vendor()}},
            )
            events.append(av_analysis)
        entities.append(root)

        self.entities = list(set(entities))
        self.relations = list(set(relations))
        self.events = list(set(events))

    def get_results(self) -> ([Entity], [EntityRelation], [Event]):
        return self.entities, self.relations, self.events
