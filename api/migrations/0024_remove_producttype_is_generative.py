# Generated by Django 5.0.4 on 2024-05-20 06:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0023_alter_product_thumbnail'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='producttype',
            name='is_generative',
        ),
    ]
