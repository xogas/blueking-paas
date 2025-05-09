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

from typing import Dict, List

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from paasng.infras.iam.permissions.resources.application import AppAction
from paasng.infras.iam.utils import get_app_actions_by_role
from paasng.platform.applications.constants import ApplicationRole
from paasng.utils.serializers import UserField


class RoleField(serializers.Field):
    """Role field for present role object friendly"""

    def to_representation(self, value):
        return {"id": value, "name": ApplicationRole(value).name.lower()}

    def to_internal_value(self, data):
        try:
            role_id = data["id"]
        except Exception:
            raise ValidationError('Incorrect role param. Expected like {role: {"id": 3}}.')
        try:
            ApplicationRole(role_id)
        except Exception:
            raise ValidationError(_("%s 不是合法选项") % role_id)
        return role_id


class ApplicationMembershipSLZ(serializers.Serializer):
    """平台管理 - 应用成员序列化器"""

    user = UserField()
    roles = serializers.ListField(child=RoleField(), help_text="用户角色列表")


class PermissionModelOutputSLZ(serializers.Serializer):
    """权限模型序列化器"""

    name = serializers.CharField(help_text="角色名称")
    label = serializers.SerializerMethodField(help_text="角色名称标签")
    actions = serializers.SerializerMethodField(help_text="角色权限列表")

    def get_label(self, obj) -> str:
        role = ApplicationRole[obj["name"].upper()]
        return role.get_choice_label(role)

    def get_actions(self, obj) -> List[Dict[str, str]]:
        role = ApplicationRole[obj["name"].upper()]
        app_actions = get_app_actions_by_role(role)
        actions = [
            {
                "action": action,
                "label": AppAction.get_choice_label(action),
            }
            for action in app_actions
        ]
        return actions
