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

from paasng.utils.basic import re_path

from . import views

urlpatterns = [
    re_path(r"^api/user/$", views.UserInfoViewSet.as_view(), name="api.accounts.user"),
    re_path(
        r"^api/accounts/feature_flags/$",
        views.AccountFeatureFlagViewSet.as_view({"get": "list"}),
        name="api.accounts.feature_flags",
    ),
    re_path(r"^api/accounts/userinfo/$", views.UserInfoViewSet.as_view(), name="api.accounts.userinfo"),
    re_path(
        r"^api/accounts/verification/generation/$",
        views.UserVerificationGenerationView.as_view(),
        name="api.accounts.verification.generation",
    ),
    re_path(
        r"^api/accounts/verification/validation/$",
        views.UserVerificationValidationView.as_view(),
        name="api.accounts.verification.validation",
    ),
    re_path(
        r"^api/accounts/oauth/token/$",
        views.OauthTokenViewSet.as_view({"get": "fetch_paasv3cli_token"}),
        name="api.accounts.oauth.token",
    ),
    re_path(r"^api/oauth/backends/$", views.Oauth2BackendsViewSet.as_view({"get": "list"})),
    re_path(
        r"^api/oauth/backends/(?P<backend>[^/]+)/(?P<pk>[^/]+)/$",
        views.Oauth2BackendsViewSet.as_view({"delete": "disconnect"}),
    ),
    # for provider call back
    re_path(r"^api/oauth/complete/(?P<backend>[^/]+)/?$", views.Oauth2BackendsViewSet.as_view({"get": "bind"})),
    # specs APIs
    re_path(
        r"^api/bkapps/regions/specs", views.RegionSpecsViewSet.as_view({"get": "retrieve"}), name="api.region.specs"
    ),
]
