# Generated by Django 4.0.10 on 2023-04-05 12:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0013_alter_event_options_event_created_at_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='entity',
            options={'ordering': ['type', 'name'], 'verbose_name': 'Entity', 'verbose_name_plural': 'Entities'},
        ),
        migrations.AlterModelOptions(
            name='event',
            options={'ordering': ['-first_seen']},
        ),
    ]
