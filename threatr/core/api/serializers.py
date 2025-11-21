from json import JSONEncoder
from uuid import UUID

from rest_framework import serializers

from threatr.core.api.models import AvailableModule, WorkerStatus, ServerStatus
from threatr.core.models import (
    EntitySuperType,
    EntityType,
    Request,
    Entity,
    EntityRelation,
    Event,
)

old_default = JSONEncoder.default


def new_default(self, obj):
    if isinstance(obj, UUID):
        return str(obj)
    return old_default(self, obj)


JSONEncoder.default = new_default


class EntitySuperTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EntitySuperType
        fields = ["name", "short_name", "description", "nf_icon"]


class EntityTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EntityType
        fields = ["name", "short_name", "description", "nf_icon"]


class FullEntitySuperTypeSerializer(serializers.ModelSerializer):
    sub_types = EntityTypeSerializer(many=True)

    class Meta:
        model = EntitySuperType
        fields = "__all__"


class EntitySerializer(serializers.ModelSerializer):
    super_type = EntitySuperTypeSerializer()
    type = EntityTypeSerializer()

    class Meta:
        model = Entity
        fields = "__all__"


class AvailableModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = AvailableModule
        fields = "__all__"


class WorkerStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkerStatus
        fields = "__all__"


class ServerStatusSerializer(serializers.ModelSerializer):
    available_modules = AvailableModuleSerializer(many=True, read_only=True)
    workers = WorkerStatusSerializer(many=True, read_only=True)

    class Meta:
        model = ServerStatus
        exclude = ["_id"]


class EntityRelationSerializer(serializers.ModelSerializer):
    # obj_from = EntitySerializer(many=False, read_only=True)
    # obj_to = EntitySerializer(many=False, read_only=True)
    class Meta:
        model = EntityRelation
        fields = [
            "id",
            "name",
            "description",
            "created_at",
            "attributes",
            "obj_from",
            "obj_to",
        ]


class EventSerializer(serializers.ModelSerializer):
    type = EntityTypeSerializer()

    class Meta:
        model = Event
        fields = "__all__"


class RequestSerializer(serializers.ModelSerializer):
    super_type = EntitySuperTypeSerializer()
    type = EntityTypeSerializer()

    class Meta:
        model = Request
        fields = ["id", "value", "super_type", "type", "status", "created_at"]
