# Generated by Django 4.0.10 on 2023-03-12 12:04

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0008_event_description'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='entityrelation',
            name='request',
        ),
    ]