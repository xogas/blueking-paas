# Generated by Django 4.2.16 on 2024-12-09 09:11

from django.db import migrations, models
import django.db.models.deletion
import paasng.utils.models


class Migration(migrations.Migration):

    dependencies = [
        ('modules', '0016_auto_20240904_1439'),
        ('applications', '0013_applicationdeploymentmoduleorder'),
    ]

    operations = [
        migrations.AddField(
            model_name='applicationdeploymentmoduleorder',
            name='user',
            field=paasng.utils.models.BkUserField(blank=True, db_index=True, max_length=64, null=True),
        ),
        migrations.AlterField(
            model_name='applicationdeploymentmoduleorder',
            name='module',
            field=models.ForeignKey(db_constraint=False, on_delete=django.db.models.deletion.CASCADE, to='modules.module', verbose_name='模块'),
        ),
        migrations.AlterUniqueTogether(
            name='applicationdeploymentmoduleorder',
            unique_together={('user', 'module')},
        ),
    ]
