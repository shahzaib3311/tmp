# Generated by Django 5.0.4 on 2024-05-12 23:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0008_alter_product_product_price'),
    ]

    operations = [
        migrations.AddField(
            model_name='order',
            name='totalPrice',
            field=models.FloatField(default=0.0),
        ),
    ]
