# Generated by Django 5.0.4 on 2024-05-12 21:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0007_alter_orderedproduct_custom_img'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='product_price',
            field=models.FloatField(default=0),
        ),
    ]
