# Generated by Django 4.0.10 on 2023-03-13 12:57

import django.contrib.postgres.fields.hstore
from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0009_remove_entityrelation_request'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='event',
            options={'ordering': ['type', 'first_seen']},
        ),
        migrations.AlterModelOptions(
            name='request',
            options={'ordering': ['-created_at']},
        ),
        migrations.CreateModel(
            name='VendorCredentials',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, help_text='Unique identifier.', primary_key=True, serialize=False)),
                ('vendor', models.CharField(default='', max_length=512, verbose_name='vendor identifier')),
                ('credentials', django.contrib.postgres.fields.hstore.HStoreField(default=dict)),
            ],
            options={
                'unique_together': {('vendor', 'credentials')},
            },
        ),
    ]
