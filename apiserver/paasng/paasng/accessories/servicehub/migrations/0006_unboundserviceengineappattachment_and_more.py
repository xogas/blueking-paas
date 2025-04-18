# Generated by Django 4.2.16 on 2024-12-25 09:35

from django.db import migrations, models
import django.db.models.deletion
import paasng.utils.models


class Migration(migrations.Migration):

    dependencies = [
        ('engine', '0023_remove_deployment_hooks_remove_deployment_procfile'),
        ('services', '0006_alter_servicecategory_name_en'),
        ('servicehub', '0005_servicebindingpolicy_servicebindingprecedencepolicy'),
    ]

    operations = [
        migrations.CreateModel(
            name='UnboundServiceEngineAppAttachment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('region', models.CharField(help_text='部署区域', max_length=32)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('owner', paasng.utils.models.BkUserField(blank=True, db_index=True, max_length=64, null=True)),
                ('engine_app', models.ForeignKey(db_constraint=False, on_delete=django.db.models.deletion.CASCADE, related_name='unbound_service_attachment', to='engine.engineapp', verbose_name='蓝鲸引擎应用')),
                ('service', models.ForeignKey(db_constraint=False, on_delete=django.db.models.deletion.CASCADE, to='services.service', verbose_name='增强服务')),
                ('service_instance', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.CASCADE, to='services.serviceinstance', verbose_name='增强服务实例')),
            ],
            options={
                'verbose_name': 'unbound attachment between local service and engine app',
                'unique_together': {('service', 'engine_app', 'service_instance')},
            },
        ),
        migrations.CreateModel(
            name='UnboundRemoteServiceEngineAppAttachment',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('region', models.CharField(help_text='部署区域', max_length=32)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('owner', paasng.utils.models.BkUserField(blank=True, db_index=True, max_length=64, null=True)),
                ('service_id', models.UUIDField(verbose_name='远程增强服务 ID')),
                ('service_instance_id', models.UUIDField(null=True, verbose_name='远程增强服务实例 ID')),
                ('engine_app', models.ForeignKey(db_constraint=False, on_delete=django.db.models.deletion.CASCADE, related_name='unbound_remote_service_attachment', to='engine.engineapp', verbose_name='蓝鲸引擎应用')),
            ],
            options={
                'verbose_name': 'unbound attachment between remote service and engine app',
                'unique_together': {('service_id', 'engine_app', 'service_instance_id')},
            },
        ),
    ]
