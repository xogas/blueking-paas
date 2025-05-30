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

from typing import List

import cattr
import pytest

from paas_wl.bk_app.processes.models import ProcessSpecManager, ProcessTmpl
from paas_wl.infras.cluster.utils import get_cluster_by_app
from paas_wl.workloads.networking.ingress.constants import AppDomainSource
from paas_wl.workloads.networking.ingress.kres_entities.ingress import ingress_kmodel
from paas_wl.workloads.networking.ingress.managers.misc import AppDefaultIngresses, LegacyAppIngressMgr
from paas_wl.workloads.networking.ingress.models import AppDomain
from paas_wl.workloads.networking.ingress.utils import make_service_name

pytestmark = pytest.mark.django_db(databases=["default", "workloads"])


class TestLegacyAppIngressMgr:
    def test_list_desired_domains(self, bk_stag_wl_app):
        ingress_mgr = LegacyAppIngressMgr(bk_stag_wl_app)
        domains = ingress_mgr.list_desired_domains()
        cluster = get_cluster_by_app(bk_stag_wl_app)
        assert len(domains) == 1
        assert (
            domains[0].host
            == cluster.ingress_config.default_ingress_domain_tmpl % bk_stag_wl_app.scheduler_safe_name_with_region
        )

    @pytest.mark.auto_create_ns
    def test_set_header_x_script_name(self, bk_stag_wl_app):
        ingress_mgr = LegacyAppIngressMgr(bk_stag_wl_app)
        ingress_mgr.sync(default_service_name="foo")
        ingress = ingress_kmodel.get(bk_stag_wl_app, name=ingress_mgr.make_ingress_name())
        assert ingress.set_header_x_script_name is False
        assert (
            ingress._kube_data["metadata"]["annotations"]["nginx.ingress.kubernetes.io/configuration-snippet"]
            == ingress.configuration_snippet
        )
        ingress_mgr.delete()


@pytest.mark.mock_get_structured_app
@pytest.mark.auto_create_ns
class TestAppDefaultIngresses:
    def test_integrated(self, bk_stag_wl_app):
        app_default_ingresses = AppDefaultIngresses(bk_stag_wl_app)
        app_default_ingresses.sync_ignore_empty(default_service_name="foo")
        assert len(ingress_kmodel.list_by_app(bk_stag_wl_app)) == 1

        AppDomain.objects.create(
            app=bk_stag_wl_app, tenant_id=bk_stag_wl_app.tenant_id, host="bar-2.com", source=AppDomainSource.AUTO_GEN
        )

        app_default_ingresses.sync_ignore_empty(default_service_name="foo")
        assert len(ingress_kmodel.list_by_app(bk_stag_wl_app)) == 2

        ret = app_default_ingresses.safe_update_target(service_name="foo-copy", service_port_name="foo-port-copy")
        assert ret.num_of_successful > 0
        for ingress in ingress_kmodel.list_by_app(bk_stag_wl_app):
            assert ingress.service_name == "foo-copy"
            assert ingress.service_port_name == "foo-port-copy"

        app_default_ingresses.delete_if_service_matches(service_name="not-matched")
        assert len(ingress_kmodel.list_by_app(bk_stag_wl_app)) == 2

        app_default_ingresses.delete_if_service_matches(service_name="foo-copy")
        assert len(ingress_kmodel.list_by_app(bk_stag_wl_app)) == 0

    def test_set_header_x_script_name(self, bk_stag_wl_app):
        AppDomain.objects.create(
            app=bk_stag_wl_app, tenant_id=bk_stag_wl_app.tenant_id, host="bar-2.com", source=AppDomainSource.AUTO_GEN
        )
        ingress_mgr = AppDefaultIngresses(bk_stag_wl_app)
        ingress_mgr.sync_ignore_empty(default_service_name="foo")

        ingresses = ingress_kmodel.list_by_app(bk_stag_wl_app)
        assert len(ingresses) == 2

        for ingress in ingresses:
            if ingress.name == LegacyAppIngressMgr(bk_stag_wl_app).make_ingress_name():
                continue
            assert ingress.set_header_x_script_name is True
            assert (
                "X-Script-Name"
                in ingress._kube_data["metadata"]["annotations"]["nginx.ingress.kubernetes.io/configuration-snippet"]
            )
            assert "X-Script-Name" not in ingress.configuration_snippet

    def test_restore_default_service(self, bk_stag_wl_app):
        mgr = AppDefaultIngresses(bk_stag_wl_app)
        svc_name_default = make_service_name(bk_stag_wl_app, "web")
        mgr.sync_ignore_empty(default_service_name=svc_name_default)

        # Update service name to "worker" and check
        svc_name_worker = make_service_name(bk_stag_wl_app, "worker")
        mgr.safe_update_target(svc_name_worker, "http")
        assert ingress_kmodel.list_by_app(bk_stag_wl_app)[0].service_name == svc_name_worker

        # Set the app's process, add a process called "worker", sync ingresses, service name field
        # should remain intact because the process is there.
        ProcessSpecManager(bk_stag_wl_app).sync(
            cattr.structure([{"name": "worker", "command": "foo"}], List[ProcessTmpl])
        )
        mgr.sync_ignore_empty(default_service_name=svc_name_default)
        assert ingress_kmodel.list_by_app(bk_stag_wl_app)[0].service_name == svc_name_worker

        # Remove "worker" process and do another sync, the service name should be restored to default
        ProcessSpecManager(bk_stag_wl_app).sync([])
        mgr.sync_ignore_empty(default_service_name=svc_name_default)
        assert ingress_kmodel.list_by_app(bk_stag_wl_app)[0].service_name == svc_name_default
