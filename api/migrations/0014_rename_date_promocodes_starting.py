# Generated by Django 5.0.4 on 2024-05-13 06:29

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_remove_promocodes_deadline_promocodes_discount_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='promocodes',
            old_name='date',
            new_name='starting',
        ),
    ]
