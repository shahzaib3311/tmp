# Generated by Django 5.0.4 on 2024-05-18 07:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0022_product_discount_price'),
    ]

    operations = [
        migrations.AlterField(
            model_name='product',
            name='thumbnail',
            field=models.ImageField(default='defaults/product_def.jpg', upload_to='product/media/'),
        ),
    ]
