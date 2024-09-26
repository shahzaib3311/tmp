# Generated by Django 5.0.4 on 2024-07-02 16:54

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0031_remove_orderedproduct_custom_img_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ordereddesign',
            name='image',
        ),
        migrations.RemoveField(
            model_name='ordereddesign',
            name='order',
        ),
        migrations.RemoveField(
            model_name='userdesigncart',
            name='image',
        ),
        migrations.AddField(
            model_name='ordereddesign',
            name='design',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='api.design'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='ordereddesign',
            name='user',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='userdesigncart',
            name='design',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='api.design'),
            preserve_default=False,
        ),
        migrations.CreateModel(
            name='OrderedCustom',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.IntegerField(default=1)),
                ('size', models.CharField(max_length=10)),
                ('image', models.ImageField(upload_to='custom/images/')),
                ('shirt_style', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.shirtstyle')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserCustomCart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.IntegerField(default=1)),
                ('size', models.CharField(max_length=10)),
                ('image', models.ImageField(upload_to='custom/images/')),
                ('shirt_style', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='api.shirtstyle')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
