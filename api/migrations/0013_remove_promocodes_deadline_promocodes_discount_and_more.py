# Generated by Django 5.0.4 on 2024-05-13 06:29

import api.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0012_promocodes_order_promo_used_userpromohistory'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='promocodes',
            name='deadline',
        ),
        migrations.AddField(
            model_name='promocodes',
            name='discount',
            field=models.FloatField(default=0),
        ),
        migrations.AddField(
            model_name='promocodes',
            name='discount_type',
            field=models.CharField(choices=[('percentage', 'Percentage'), ('value', 'Value')], default='percentage', max_length=10),
        ),
        migrations.AddField(
            model_name='promocodes',
            name='expiry',
            field=models.DateField(default=api.models.get_default_expiry),
        ),
        migrations.AlterField(
            model_name='promocodes',
            name='code',
            field=models.CharField(max_length=6, unique=True),
        ),
    ]
