# Generated by Django 5.0.4 on 2024-05-14 05:19

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0015_producttype_product_product_size'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='product',
            name='product_type',
        ),
    ]