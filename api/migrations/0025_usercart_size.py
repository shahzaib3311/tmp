# Generated by Django 5.0.4 on 2024-05-21 18:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0024_remove_producttype_is_generative'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercart',
            name='size',
            field=models.CharField(default='s', max_length=10),
            preserve_default=False,
        ),
    ]
