# Generated by Django 5.0.4 on 2024-05-14 05:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0016_remove_product_product_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='producttype',
            name='is_generative',
            field=models.BooleanField(default=False),
        ),
    ]
