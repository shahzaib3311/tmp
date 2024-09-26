# Generated by Django 5.0.4 on 2024-06-30 19:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_usercart_size'),
    ]

    operations = [
        migrations.CreateModel(
            name='Design',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('design_name', models.CharField(max_length=50)),
                ('design_detail', models.CharField(max_length=255)),
                ('design_price', models.FloatField(default=0)),
                ('discount_price', models.FloatField(default=None, null=True)),
                ('image', models.ImageField(default='defaults/product_def.jpg', upload_to='designs/premade/')),
            ],
        ),
    ]
