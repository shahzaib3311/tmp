# Generated by Django 5.0.4 on 2024-05-14 05:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_product_product_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='product',
            name='product_size',
        ),
    ]
