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

from functools import wraps
from typing import Dict

from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import BasePermission

from paasng.infras.accounts.constants import SiteRole
from paasng.infras.accounts.models import UserProfile

from .base import ProtectedResource
from .constants import SiteAction


class GlobalSiteResource(ProtectedResource):
    permissions = [
        (SiteAction.VISIT_SITE, "can visit site"),
        (SiteAction.VISIT_ADMIN42, "can visit admin pages"),
        # Admin42
        (SiteAction.MANAGE_PLATFORM, "can manage platform"),
        (SiteAction.MANAGE_APP_TEMPLATES, "can manage app templates"),
        (SiteAction.OPERATE_PLATFORM, "can operate platform"),
    ]

    def _get_role_of_user(self, user, obj) -> SiteRole:
        """Get user role of site"""
        if not user.is_authenticated:
            return SiteRole.NOBODY

        try:
            profile = UserProfile.objects.get_profile(user)
        except UserProfile.DoesNotExist:
            return SiteRole.NOBODY

        return SiteRole(profile.role)


def gen_site_role_perm_map(role: SiteRole) -> Dict[SiteAction, bool]:
    """根据不同的用户角色，生成对应的权限映射表"""

    perm_map = {
        SiteAction.VISIT_SITE: True,
        SiteAction.VISIT_ADMIN42: False,
        SiteAction.MANAGE_PLATFORM: False,
        SiteAction.MANAGE_APP_TEMPLATES: False,
        SiteAction.OPERATE_PLATFORM: False,
    }

    if role == SiteRole.BANNED_USER:
        perm_map[SiteAction.VISIT_SITE] = False

    elif role in [SiteRole.ADMIN, SiteRole.SUPER_USER]:
        perm_map[SiteAction.VISIT_ADMIN42] = True
        perm_map[SiteAction.MANAGE_PLATFORM] = True
        perm_map[SiteAction.MANAGE_APP_TEMPLATES] = True
        perm_map[SiteAction.OPERATE_PLATFORM] = True

    elif role == SiteRole.PLATFORM_MANAGER:
        perm_map[SiteAction.VISIT_ADMIN42] = True
        perm_map[SiteAction.MANAGE_PLATFORM] = True

    elif role == SiteRole.APP_TEMPLATES_MANAGER:
        perm_map[SiteAction.VISIT_ADMIN42] = True
        perm_map[SiteAction.MANAGE_APP_TEMPLATES] = True

    elif role == SiteRole.PLATFORM_OPERATOR:
        perm_map[SiteAction.VISIT_ADMIN42] = True
        perm_map[SiteAction.OPERATE_PLATFORM] = True

    return perm_map


def _init_global_site_resource():
    resource = GlobalSiteResource()
    resource.add_nobody_role()

    for role in [
        SiteRole.USER,
        SiteRole.ADMIN,
        SiteRole.SUPER_USER,
        SiteRole.BANNED_USER,
        SiteRole.PLATFORM_MANAGER,
        SiteRole.APP_TEMPLATES_MANAGER,
        SiteRole.PLATFORM_OPERATOR,
    ]:
        resource.add_role(role, gen_site_role_perm_map(role))

    return resource


global_site_resource = _init_global_site_resource()


def site_perm_class(action: SiteAction):
    """构建 DRF 可用的权限类，管理站点访问相关权限。"""

    class Permission(BasePermission):
        # used to check if is admin42 permission
        perm_action = action

        def has_permission(self, request, *args, **kwargs):
            if not user_has_site_action_perm(request.user, action):
                raise PermissionDenied("You are not allowed to do this operation.")
            return True

        def has_object_permission(self, request, view, obj):
            if not user_has_site_action_perm(request.user, action):
                raise PermissionDenied("You are not allowed to do this operation.")
            return True

    return Permission


def site_perm_required(action: SiteAction):
    """平台控制的权限，接入了权限中心的需要使用 admin42 模块中的方法"""

    if not global_site_resource.has_permission(action):
        raise ValueError(f'"{action}" is not a valid permission name for Site')

    def decorated(func):
        # Set an attribute to mark the function as protected so that the `perm_insure`
        # module knows.
        func._protected_by_site_perm_required = True

        @wraps(func)
        def view_func(self, request, *args, **kwargs):
            role = global_site_resource.get_role_of_user(request.user, "site")
            if not role.has_perm(action):
                raise PermissionDenied("You are not allowed to do this operation.")

            return func(self, request, *args, **kwargs)

        return view_func

    return decorated


def user_has_site_action_perm(user, action: SiteAction):
    """检查指定用户是否有某操作的权限"""
    role = global_site_resource.get_role_of_user(user, action)
    return role.has_perm(action)
