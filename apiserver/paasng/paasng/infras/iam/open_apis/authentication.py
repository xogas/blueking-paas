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

from django.conf import settings
from iam import IAM
from rest_framework.authentication import BasicAuthentication
from rest_framework.exceptions import AuthenticationFailed as RESTAuthenticationFailed

from paasng.core.tenant.user import get_init_tenant_id

from .exceptions import AuthenticationFailed


class IAMBasicAuthentication(BasicAuthentication):
    """自定义认证逻辑, 对权限中心请求认证"""

    def authenticate(self, request):
        try:
            result = super().authenticate(request)
            if result is None:
                raise AuthenticationFailed("basic auth failed")
        except RESTAuthenticationFailed as e:
            raise AuthenticationFailed(str(e))
        return result

    def authenticate_credentials(self, userid: str, password: str, request=None):
        if userid != "bk_iam":
            raise AuthenticationFailed("username is not bk_iam")

        _iam = IAM(
            settings.IAM_APP_CODE,
            settings.IAM_APP_SECRET,
            settings.BK_IAM_APIGATEWAY_URL,
            bk_tenant_id=get_init_tenant_id(),
        )
        ok, msg, token = _iam.get_token(settings.IAM_PAAS_V3_SYSTEM_ID)
        if not ok:
            raise AuthenticationFailed(f"get system token fail: {msg}")
        if password != token:
            raise AuthenticationFailed("password in basic_auth not equals to system token")

        return ({"username": userid, "password": password}, None)
