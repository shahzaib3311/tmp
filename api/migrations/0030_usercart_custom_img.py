# Generated by Django 5.0.4 on 2024-07-01 21:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0029_shirtstyle_remove_usercart_custom_img_ordereddesign_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='usercart',
            name='custom_img',
            field=models.ImageField(default=None, null=True, upload_to='orders/images/'),
        ),
    ]