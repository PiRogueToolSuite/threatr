from django.db import models


class AvailableModule(models.Model):
    class Meta:
        managed = False

    id = models.CharField(max_length=128, primary_key=True)
    vendor = models.CharField(max_length=256)
    configured = models.IntegerField(default=0)
    description = models.TextField()
    supported_types = []


class ServerStatus(models.Model):
    class Meta:
        managed = False

    id = models.BigAutoField(primary_key=True)
    git_commit_hash = models.CharField(max_length=256, primary_key=False)
    available_modules = []
    workers = []
    cached_entities = models.IntegerField(default=0)
    cached_events = models.IntegerField(default=0)
    cached_relations = models.IntegerField(default=0)


class WorkerStatus(models.Model):
    class Meta:
        managed = False

    id = models.CharField(max_length=128, primary_key=True)
    status = models.CharField(max_length=64)
    uptime = models.FloatField(default=0.)
    enqueued_tasks = models.IntegerField(default=0)
    available_results = models.IntegerField(default=0)
