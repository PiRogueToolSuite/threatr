import uuid

from django.contrib.postgres.fields import HStoreField
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _


class VendorCredentials(models.Model):
    class Meta:
        ordering = ["last_usage"]
        unique_together = ["vendor", "credentials"]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        help_text=_("Unique identifier."),
        editable=False,
    )
    vendor = models.CharField(
        max_length=512, verbose_name=_("vendor identifier"), default=""
    )
    last_usage = models.DateTimeField(default=timezone.now)
    credentials = HStoreField(default=dict)


class EntitySuperType(models.Model):
    class Meta:
        ordering = ["name"]
        verbose_name = "Entity super-type"
        verbose_name_plural = "Entity super-types"

    short_name = models.CharField(primary_key=True, max_length=32, unique=True)
    name = models.CharField(
        max_length=512,
        verbose_name=_("name"),
        help_text=_("Give a meaningful name to this type of entity."),
        default="",
    )
    description = models.TextField(
        help_text=_("Add more details about it."), blank=True, null=True
    )
    svg_icon = models.TextField(blank=True, null=True)
    nf_icon = models.CharField(max_length=256, blank=True, null=True)

    @property
    def children_types(self):
        return self.sub_types.all()

    @staticmethod
    def get_types() -> dict:
        super_types = {}
        for t in EntitySuperType.objects.all():
            super_types[t.short_name] = t
        return super_types

    def __str__(self):
        return self.name


class EntityType(models.Model):
    class Meta:
        ordering = ["name"]
        verbose_name = "Entity type"
        verbose_name_plural = "Entity types"
        unique_together = ["short_name", "super_type"]

    short_name = models.CharField(max_length=32, primary_key=True, unique=True)
    name = models.CharField(
        max_length=512,
        verbose_name=_("name"),
        help_text=_("Give a meaningful name to this type of entity."),
        default="",
    )
    description = models.TextField(
        help_text=_("Add more details about it."), blank=True, null=True
    )
    svg_icon = models.TextField(blank=True, null=True)
    nf_icon = models.CharField(max_length=256, blank=True, null=True)
    super_type = models.ForeignKey(
        EntitySuperType, on_delete=models.CASCADE, related_name="sub_types"
    )

    @staticmethod
    def get_types(super_type: str) -> dict:
        sub_types = {}
        for t in EntityType.objects.filter(super_type=super_type.upper()):
            sub_types[t.short_name] = t
        return sub_types

    def __str__(self):
        return self.name


class Request(models.Model):
    class Meta:
        ordering = ["-created_at"]

    class Status(models.TextChoices):
        CREATED = "CREATED", _("Created")
        ENQUEUED = "ENQUEUED", _("Enqueued")
        PROCESSING = "PROCESSING", _("Processing")
        POST_PROCESSING = "POST_PROCESSING", _("Post processing")
        SUCCEEDED = "SUCCEEDED", _("Succeeded")
        CANCELLED = "CANCELLED", _("Cancelled")
        FAILED = "FAILED", _("Failed")

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        help_text=_("Unique identifier."),
        editable=False,
    )
    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Creation date of this object."), editable=False
    )
    value = models.TextField(help_text=_("Value of the observable to be queried."))
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.CREATED,
    )
    super_type = models.ForeignKey(
        EntitySuperType,
        on_delete=models.CASCADE,
        related_name="request_super_type",
    )
    type = models.ForeignKey(
        EntityType,
        on_delete=models.CASCADE,
        related_name="request_type",
    )


class Entity(models.Model):
    RED = "RED"
    AMBER = "AMBER"
    GREEN = "GREEN"
    WHITE = "WHITE"
    TLP_PAP_CHOICES = [
        (RED, "RED"),
        (AMBER, "AMBER"),
        (GREEN, "GREEN"),
        (WHITE, "WHITE"),
    ]

    class Meta:
        ordering = ["type", "name"]
        verbose_name = "Entity"
        verbose_name_plural = "Entities"
        unique_together = ["name", "super_type", "type"]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        help_text=_("Unique identifier."),
        editable=False,
    )
    name = models.CharField(
        max_length=512,
        verbose_name=_("name"),
        help_text=_("Give a meaningful name to this entity."),
    )
    description = models.TextField(
        help_text=_("Add more details about this object."), null=True, blank=True
    )
    source_url = models.URLField(
        help_text=_("Specify the source of this object."),
        verbose_name="Source URL",
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Creation date of this object."), editable=False
    )
    updated_at = models.DateTimeField(
        help_text=_("Latest modification of this object."), auto_now=True
    )
    super_type = models.ForeignKey(
        EntitySuperType,
        on_delete=models.CASCADE,
        related_name="super_type_of",
        related_query_name="q_super_type_of",
    )
    type = models.ForeignKey(
        EntityType,
        on_delete=models.CASCADE,
        related_name="type_of",
        related_query_name="q_type_of",
    )
    tlp = models.CharField(
        max_length=6,
        choices=TLP_PAP_CHOICES,
        help_text=_(
            "Traffic Light Protocol, designed to indicate the sharing boundaries to be applied."
        ),
        verbose_name="TLP",
        default=WHITE,
    )
    pap = models.CharField(
        max_length=6,
        choices=TLP_PAP_CHOICES,
        help_text=_(
            "Permissible Actions Protocol, designed to indicate how the received information can be used."
        ),
        verbose_name="PAP",
        default=WHITE,
    )
    attributes = HStoreField(default=dict)

    def __eq__(self, other):
        if not other:
            return False
        return str(self.id) == str(other.id)

    def __hash__(self):
        return hash(str(self.id))

    def __str__(self):
        return f"{self.name} ({self.type.name})"

    def get_relations(self):
        relations = EntityRelation.objects.filter(
            Q(obj_from_id=self.id) | Q(obj_to_id=self.id)
        ).all()
        return relations

    def get_in_relations(self):
        relations = EntityRelation.objects.filter(obj_to_id=self.id).all()
        return relations

    def get_out_relations(self):
        relations = EntityRelation.objects.filter(obj_from_id=self.id).all()
        return relations

    @property
    def relations(self):
        return self.get_relations()

    @property
    def in_relations(self):
        return self.get_in_relations()

    @property
    def out_relations(self):
        return self.get_out_relations()


class EntityRelation(models.Model):
    class Meta:
        unique_together = ["name", "obj_from_id", "obj_to_id"]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        help_text=_("Unique identifier."),
        editable=False,
    )
    name = models.CharField(
        max_length=512,
        help_text=_("Name of this relation between two entities."),
    )
    description = models.TextField(
        help_text=_("Add more details about this object."), null=True, blank=True
    )
    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Creation date of this object."), editable=False
    )
    attributes = HStoreField(default=dict)
    obj_from = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name="source_of_relation"
    )
    obj_to = models.ForeignKey(
        Entity, on_delete=models.CASCADE, related_name="target_of_relation"
    )

    def __eq__(self, other):
        if not other:
            return False
        return str(self.id) == str(other.id)

    def __hash__(self):
        return hash(str(self.id))

    def __str__(self):
        return f"{self.name} ({self.obj_from} -> {self.obj_to})"


class Event(models.Model):
    class Meta:
        ordering = ["-first_seen"]
        unique_together = ["type", "name", "first_seen", "last_seen", "involved_entity"]

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        help_text=_("Unique identifier."),
        editable=False,
    )
    type = models.ForeignKey(
        EntityType, on_delete=models.CASCADE, help_text=_("Type of this event.")
    )
    first_seen = models.DateTimeField(
        help_text=_("First time the event has occurred."), default=timezone.now
    )
    last_seen = models.DateTimeField(
        help_text=_("First time the event has occurred."), default=timezone.now
    )
    count = models.BigIntegerField(
        help_text=_("How many times this event has occurred."), default=0
    )
    name = models.CharField(
        max_length=512,
    )
    created_at = models.DateTimeField(
        auto_now_add=True, help_text=_("Creation date of this object."), editable=False
    )
    updated_at = models.DateTimeField(
        help_text=_("Latest modification of this object."), auto_now=True
    )
    description = models.TextField(
        help_text=_("Add more details about this object."), null=True, blank=True
    )
    involved_entity = models.ForeignKey(
        Entity,
        on_delete=models.CASCADE,
    )
    attributes = HStoreField(default=dict)

    def __str__(self):
        return self.name

    def __eq__(self, other):
        if not other:
            return False
        return str(self.id) == str(other.id)

    def __hash__(self):
        return hash(str(self.id))
