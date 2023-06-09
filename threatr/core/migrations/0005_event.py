# Generated by Django 4.0.10 on 2023-03-10 14:27

import django.contrib.postgres.fields.hstore
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_alter_entity_name_alter_entity_unique_together'),
    ]

    operations = [
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, help_text='Unique identifier.', primary_key=True, serialize=False)),
                ('first_seen', models.DateTimeField(default=django.utils.timezone.now, help_text='First time the event has occurred.')),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now, help_text='First time the event has occurred.')),
                ('count', models.BigIntegerField(default=0, help_text='How many times this event has occurred.')),
                ('name', models.CharField(max_length=512)),
                ('attributes', django.contrib.postgres.fields.hstore.HStoreField(blank=True, null=True)),
                ('type', models.ForeignKey(help_text='Type of this event.', on_delete=django.db.models.deletion.CASCADE, to='core.entitytype')),
            ],
            options={
                'ordering': ['name'],
                'unique_together': {('type', 'name', 'first_seen', 'last_seen')},
            },
        ),
    ]
