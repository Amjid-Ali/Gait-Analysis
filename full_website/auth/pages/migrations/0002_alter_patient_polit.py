# Generated by Django 4.1.2 on 2022-10-29 05:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("pages", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="patient",
            name="polit",
            field=models.CharField(blank=True, max_length=255),
        ),
    ]
