# -*- coding: utf-8 -*-
# TencentBlueKing is pleased to support the open source community by making
# 蓝鲸智云 - PaaS 平台 (BlueKing - PaaS System) available.
# Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
# Licensed under the MIT License (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
#     http://opensource.org/licenses/MIT
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions and
# limitations under the License.
#
# We undertake not to change the open source license (MIT license) applicable
# to the current version of the project delivered to anyone in the future.

import logging
import os
from dataclasses import asdict, dataclass
from typing import Dict, List

from django.core.management.base import BaseCommand
from environ import Env

from paas_wl.infras.cluster.constants import ClusterTokenType
from paas_wl.infras.cluster.models import APIServer, Cluster

logger = logging.getLogger(__name__)


env = Env()


@dataclass
class ClusterData:
    name: str
    description: str | None = None
    ingress_config: Dict | None = None
    annotations: Dict | None = None
    ca_data: str | None = None
    cert_data: str | None = None
    key_data: str | None = None
    token_type: ClusterTokenType | None = None
    token_value: str | None = None
    default_node_selector: Dict | None = None
    default_tolerations: List | None = None
    feature_flags: Dict | None = None


@dataclass
class InitialClusterData:
    cluster_id: str
    cluster_data: ClusterData
    api_server_urls: list


class Command(BaseCommand):
    help = "Initialize the application cluster, which can overwrite the existing data in the database"

    def add_arguments(self, parser):
        parser.add_argument("--override", dest="override", action="store_true")
        parser.add_argument("--dry_run", dest="dry_run", action="store_true")

    def render_data(self) -> InitialClusterData:
        try:
            data = {
                "name": "default-main",
                "description": "默认应用集群",
                "ingress_config": {
                    "default_ingress_domain_tmpl": "%s." + env.str("PAAS_WL_CLUSTER_SUB_PATH_DOMAIN", ""),
                    "frontend_ingress_ip": env.str("PAAS_WL_CLUSTER_FRONTEND_INGRESS_IP", ""),
                    "app_root_domains": [
                        {
                            "name": env.str("PAAS_WL_CLUSTER_APP_ROOT_DOMAIN", ""),
                            "https_enabled": env.bool("PAAS_WL_CLUSTER_ENABLED_HTTPS_BY_DEFAULT", False),
                        }
                    ],
                    "sub_path_domains": [
                        {
                            "name": env.str("PAAS_WL_CLUSTER_SUB_PATH_DOMAIN", ""),
                            "https_enabled": env.bool("PAAS_WL_CLUSTER_ENABLED_HTTPS_BY_DEFAULT", False),
                        }
                    ],
                    "port_map": {
                        "http": env.int("PAAS_WL_CLUSTER_HTTP_PORT", 80),
                        "https": env.int("PAAS_WL_CLUSTER_HTTPS_PORT", 443),
                    },
                },
                "annotations": {
                    "bcs_cluster_id": env.str("PAAS_WL_CLUSTER_BCS_CLUSTER_ID", ""),
                    "bcs_project_id": env.str("PAAS_WL_CLUSTER_BCS_PROJECT_ID", ""),
                    "bk_biz_id": env.str("PAAS_WL_CLUSTER_BK_BIZ_ID", ""),
                },
                "ca_data": env.str("PAAS_WL_CLUSTER_CA_DATA", ""),
                "cert_data": env.str("PAAS_WL_CLUSTER_CERT_DATA", ""),
                "key_data": env.str("PAAS_WL_CLUSTER_KEY_DATA", ""),
                "token_type": 1,
                "token_value": env.str("PAAS_WL_CLUSTER_TOKEN_VALUE", ""),
                "default_node_selector": env.json("PAAS_WL_CLUSTER_NODE_SELECTOR", {}),
                "default_tolerations": env.json("PAAS_WL_CLUSTER_TOLERATIONS", []),
                "feature_flags": env.json("PAAS_WL_CLUSTER_FEATURE_FLAGS", {}),
            }
        except Exception as e:
            raise ValueError("default cluster data is not valid") from e

        cluster_id = "332d740b-03ed-40f2-aa6b-c90cc5f1e89c"
        cluster_data = ClusterData(**data)

        api_server_urls = os.environ.get("PAAS_WL_CLUSTER_API_SERVER_URLS")
        api_server_list = api_server_urls.split(";") if api_server_urls else []

        return InitialClusterData(cluster_id=cluster_id, cluster_data=cluster_data, api_server_urls=api_server_list)

    def handle(self, override, dry_run, *args, **options):
        data = self.render_data()

        cluster_qs = Cluster.objects.filter(pk=data.cluster_id)

        if cluster_qs.exists() and not override:
            logger.info("The cluster(pk:%s) already exists and overwriting is not allowed, skip", data.cluster_id)
            return

        if dry_run:
            logger.info("DRY-RUN: preparing to initialize the cluster, data: %s", data)
            return

        cluster = Cluster.objects.register_cluster(pk=data.cluster_id, **asdict(data.cluster_data))

        for _url in data.api_server_urls:
            APIServer.objects.get_or_create(cluster=cluster, host=_url, tenant_id=cluster.tenant_id)

        APIServer.objects.exclude(host__in=data.api_server_urls).delete()
        logger.info("The cluster was initialized successfully")
