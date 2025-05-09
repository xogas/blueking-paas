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


import pytest
from django.urls import reverse

pytestmark = pytest.mark.django_db


class TestApplicationMemberViewSet:
    def test_list(self, plat_mgt_api_client, bk_app):
        url = reverse("plat_mgt.applications.members", kwargs={"app_code": bk_app.code})
        rsp = plat_mgt_api_client.get(url)
        assert rsp.status_code == 200

    def test_upsert(self, plat_mgt_api_client, bk_app):
        url = reverse("plat_mgt.applications.members", kwargs={"app_code": bk_app.code, "username": "test_user"})
        data = {
            "role": "member",
            "description": "Updated test user",
        }
        rsp = plat_mgt_api_client.post(url, data=data)
        assert rsp.status_code == 200
        assert rsp.data["role"] == "member"

    def test_destroy(self, plat_mgt_api_client, bk_app):
        url = reverse(
            "plat_mgt.applications.members.delete", kwargs={"app_code": bk_app.code, "username": "test_user"}
        )
        rsp = plat_mgt_api_client.delete(url)
        assert rsp.status_code == 204

    def test_view_permission_model(self, plat_mgt_api_client):
        url = reverse("plat_mgt.applications.members.view_permission_model")
        rsp = plat_mgt_api_client.get(url)
        assert rsp.status_code == 200
        assert isinstance(rsp.data, list)
        assert len(rsp.data) == 3
        for role in rsp.data:
            assert "name" in role
            assert "label" in role
            assert "actions" in role
