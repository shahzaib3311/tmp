# Generated by Django 5.0.4 on 2024-05-12 23:35

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0009_order_totalprice'),
    ]

    operations = [
        migrations.CreateModel(
            name='City',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('city', models.CharField(max_length=20)),
                ('shipping_charges', models.FloatField()),
                ('is_active', models.BooleanField(default=True)),
            ],
        ),
        migrations.AddField(
            model_name='user',
            name='phone_number',
            field=models.CharField(blank=True, max_length=20),
        ),
        migrations.CreateModel(
            name='Addres',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('address', models.CharField(max_length=255)),
                ('postal_code', models.IntegerField()),
                ('is_active', models.BooleanField(default=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('city', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to='api.city')),
            ],
        ),
        migrations.AddField(
            model_name='order',
            name='shipping_addres',
            field=models.ForeignKey(default=0, on_delete=django.db.models.deletion.DO_NOTHING, to='api.addres'),
            preserve_default=False,
        ),
        migrations.DeleteModel(
            name='Profile',
        ),
    ]
