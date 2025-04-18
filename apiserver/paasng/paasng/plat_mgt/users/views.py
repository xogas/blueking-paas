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

from bkpaas_auth.models import user_id_encoder
from django.conf import settings
from django.db.transaction import atomic
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status, viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from paasng.infras.accounts.constants import AccountFeatureFlag as AFF
from paasng.infras.accounts.constants import SiteRole
from paasng.infras.accounts.models import AccountFeatureFlag, UserProfile
from paasng.infras.accounts.permissions.constants import PlatMgtAction
from paasng.infras.accounts.permissions.plat_mgt import plat_mgt_perm_class
from paasng.infras.sysapi_client.constants import ClientRole
from paasng.infras.sysapi_client.models import AuthenticatedAppAsClient, ClientPrivateToken, SysAPIClient
from paasng.misc.audit.constants import DataType, OperationEnum, OperationTarget
from paasng.misc.audit.service import DataDetail, add_admin_audit_record
from paasng.plat_mgt.users.serializers import (
    AccountFeatureFlagKindSLZ,
    AccountFeatureFlagSLZ,
    BulkCreatePlatformManagerSLZ,
    PlatformManagerSLZ,
    SystemAPIUserRoleSLZ,
    SystemAPIUserSLZ,
    UpsertAccountFeatureFlagSLZ,
    UpsertSystemAPIUserSLZ,
)
from paasng.utils.error_codes import error_codes

logger = logging.getLogger(__name__)


class PlatformManagerViewSet(viewsets.GenericViewSet):
    """平台管理员相关 API"""

    # 需要平台管理权限才能访问
    permission_classes = [IsAuthenticated, plat_mgt_perm_class(PlatMgtAction.ALL)]

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="获取平台管理员列表",
        responses={status.HTTP_200_OK: PlatformManagerSLZ(many=True)},
    )
    def list(self, request, *args, **kwargs):
        """获取平台管理员列表"""
        admin_profiles = (
            UserProfile.objects.filter(
                role__in=[SiteRole.ADMIN.value, SiteRole.SUPER_USER.value],
            )
            .order_by("-created")
            .values()
        )
        slz = PlatformManagerSLZ(admin_profiles, many=True)
        return Response(slz.data)

    @atomic
    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="批量创建平台管理员",
        request_body=BulkCreatePlatformManagerSLZ,
        responses={status.HTTP_201_CREATED: None},
    )
    def bulk_create(self, request, *args, **kwargs):
        """批量创建平台管理员"""
        slz = BulkCreatePlatformManagerSLZ(data=request.data)
        slz.is_valid(raise_exception=True)
        users = slz.validated_data["users"]

        # 创建用户名到用户ID的映射
        user_to_id = {user: user_id_encoder.encode(settings.USER_TYPE, user) for user in users}
        user_ids = list(user_to_id.values())

        # 查询已存在的用户, 用户id到模型的映射
        role = SiteRole.ADMIN.value
        existing_profiles = UserProfile.objects.filter(user__in=user_ids)
        existing_id_to_profile = {profile.user: profile for profile in existing_profiles}

        # 准备审计数据
        before_data = []
        after_data = []

        # 批量创建和更新数据
        profiles_to_update = []
        profiles_to_create = []

        # 处理所有用户
        for user, user_id in user_to_id.items():
            # 审计数据
            after_data.append({"user": user, "role": role})

            if user_id in existing_id_to_profile:
                # 已存在的用户 - 需要更新
                profile = existing_id_to_profile[user_id]
                before_data.append({"user": user, "role": profile.role})

                if profile.role != role:
                    profile.role = role
                    profiles_to_update.append(profile)
            else:
                # 不存在的用户 - 需要创建
                profiles_to_create.append(UserProfile(user=user_id, role=role))

        if profiles_to_create:
            # 批量创建用户
            UserProfile.objects.bulk_create(profiles_to_create)
        if profiles_to_update:
            # 批量更新用户
            UserProfile.objects.bulk_update(profiles_to_update, ["role"])

        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.CREATE,
            target=OperationTarget.PLAT_USER,
            data_before=DataDetail(type=DataType.RAW_DATA, data=before_data),
            data_after=DataDetail(type=DataType.RAW_DATA, data=after_data),
        )
        return Response(status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="删除平台管理员",
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    def destroy(self, request, user, *args, **kwargs):
        """删除平台管理员, 后台对应的操作为将用户的权限修改为普通用户"""
        # 将用户名编码为userid
        user_id = user_id_encoder.encode(settings.USER_TYPE, user)

        # 获取删除前的用户信息
        userprofile = UserProfile.objects.filter(user=user_id).first()
        if not userprofile:
            raise error_codes.USER_PROFILE_NOT_FOUND

        # 如果用户的权限已经不是管理员权限，直接返回 204
        if userprofile.role not in [SiteRole.ADMIN.value, SiteRole.SUPER_USER.value]:
            return Response(status=status.HTTP_204_NO_CONTENT)

        # 构建审计数据
        before_data = {"user": user, "role": userprofile.role}
        after_data = {"user": user, "role": SiteRole.USER.value}

        # 删除用户, 将权限更改为普通用户
        userprofile.role = SiteRole.USER.value
        userprofile.save(update_fields=["role"])

        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.DELETE,
            target=OperationTarget.PLAT_USER,
            data_before=DataDetail(type=DataType.RAW_DATA, data=before_data),
            data_after=DataDetail(type=DataType.RAW_DATA, data=after_data),
        )

        return Response(status=status.HTTP_204_NO_CONTENT)


class AccountFeatureFlagViewSet(viewsets.GenericViewSet):
    """用户特性管理 API"""

    permission_classes = [IsAuthenticated, plat_mgt_perm_class(PlatMgtAction.ALL)]

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="获取系统 API 权限列表",
        responses={status.HTTP_200_OK: AccountFeatureFlagKindSLZ(many=True)},
    )
    def feature_list(self, request, *args, **kwargs):
        """获取用户特性种类列表"""
        roles_data = [{"value": choice[0], "label": str(choice[1])} for choice in AFF.get_choices()]
        slz = AccountFeatureFlagKindSLZ(roles_data, many=True)
        return Response(slz.data)

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="获取用户特性列表",
        responses={status.HTTP_200_OK: AccountFeatureFlagSLZ(many=True)},
    )
    def list(self, request):
        """获取用户特性列表"""
        feature_flags = AccountFeatureFlag.objects.all()
        user_ids = [f.user for f in feature_flags]
        user_profiles = UserProfile.objects.filter(user__in=user_ids)
        user_tenant = {up.user: up.tenant_id for up in user_profiles}

        slz = AccountFeatureFlagSLZ(feature_flags, many=True, context={"user_tenant": user_tenant})
        return Response(slz.data)

    @atomic
    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="更新或创建用户特性",
        request_body=UpsertAccountFeatureFlagSLZ,
        responses={status.HTTP_201_CREATED: None},
    )
    def upsert(self, request):
        """更新或创建用户特性"""
        slz = UpsertAccountFeatureFlagSLZ(data=request.data)
        slz.is_valid(raise_exception=True)
        data = slz.validated_data

        user, feature, is_effect = data["user"], data["feature"], data["is_effect"]
        user_id = user_id_encoder.encode(settings.USER_TYPE, user)

        # 获取更新或创建前的用户特性
        feature_flag = AccountFeatureFlag.objects.filter(user=user_id, name=feature).first()

        # 构建审计数据
        before_data = []
        if feature_flag:
            before_data = [{"user": user, "feature": feature, "is_effect": feature_flag.effect}]

        # 更新或创建用户特性
        if feature_flag:
            # 更新特性
            feature_flag.effect = is_effect
            feature_flag.save(update_fields=["effect"])
        else:
            # 创建特性
            AccountFeatureFlag.objects.update_or_create(user=user_id, name=feature, defaults={"effect": is_effect})

        # 构建更新后的审计数据
        after_data = [{"user": user, "feature": feature, "is_effect": is_effect}]

        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.MODIFY_USER_FEATURE_FLAG,
            target=OperationTarget.PLAT_USER,
            data_before=DataDetail(type=DataType.RAW_DATA, data=before_data),
            data_after=DataDetail(type=DataType.RAW_DATA, data=after_data),
        )

        return Response(status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="删除用户特性",
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    def destroy(self, request, id=None, *args, **kwargs):
        """删除用户特性"""

        # 查询db中是否存有该用户特性
        try:
            feature_flag = AccountFeatureFlag.objects.get(pk=id)
        except AccountFeatureFlag.DoesNotExist:
            return error_codes.USER_FEATURE_FLAG_NOT_FOUND

        # 构建审计数据
        before_data = [{"user": feature_flag.user, "feature": feature_flag.name, "is_effect": feature_flag.effect}]

        try:
            # 删除用户特性
            feature_flag.delete()
        except Exception:
            logger.exception("Failed to delete user feature flag")
            return Response(
                {"detail": "Failed to delete user feature flag"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.DELETE,
            target=OperationTarget.PLAT_USER,
            data_before=DataDetail(type=DataType.RAW_DATA, data=before_data),
        )

        return Response(status=status.HTTP_204_NO_CONTENT)


class SystemApiUserViewSet(viewsets.GenericViewSet):
    """系统 API 用户相关 API"""

    permission_classes = [IsAuthenticated, plat_mgt_perm_class(PlatMgtAction.ALL)]

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="获取系统 API 权限列表",
        responses={status.HTTP_200_OK: SystemAPIUserRoleSLZ(many=True)},
    )
    def role_list(self, request, *args, **kwargs):
        """获取系统 API 权限种类列表"""
        roles_data = [{"value": choice[0], "label": str(choice[1])} for choice in ClientRole.get_choices()]
        slz = SystemAPIUserRoleSLZ(roles_data, many=True)
        return Response(slz.data)

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="获取系统 API 用户列表",
        responses={status.HTTP_200_OK: SystemAPIUserSLZ(many=True)},
    )
    def list(self, request, *args, **kwargs):
        """获取系统 API 用户列表"""
        # 查询所有系统 API 客户端
        sys_api_clients = SysAPIClient.objects.filter(is_active=True)
        # 获取客户端ID列表
        client_ids = [client.id for client in sys_api_clients]
        # 查询应用认证关系
        app_client_relation = AuthenticatedAppAsClient.objects.filter(client_id__in=client_ids)
        app_code_map = {relation.client_id: relation.bk_app_code for relation in app_client_relation}
        # 查询私有令牌
        private_tokens = ClientPrivateToken.objects.filter(client_id__in=client_ids)
        token_map = {client.client: client.token for client in private_tokens}

        # 组装数据
        result = []
        for client in sys_api_clients:
            client_data = {
                "name": client.name,
                "bk_app_code": app_code_map.get(client.id, ""),
                "private_token": token_map.get(client.id, ""),
                "role": client.role,
                "updated": client.updated,
            }
            result.append(client_data)

        slz = SystemAPIUserSLZ(result, many=True)
        return Response(slz.data)

    @atomic
    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="创建系统 API 用户",
        request_body=UpsertSystemAPIUserSLZ,
        responses={status.HTTP_201_CREATED: None},
    )
    def create(self, request, *args, **kwargs):
        """创建系统 API 用户"""
        slz = UpsertSystemAPIUserSLZ(data=request.data)
        slz.is_valid(raise_exception=True)
        data = slz.validated_data

        bk_app_code, role = data["bk_app_code"], data["role"]

        # 使用与管理命令 create_authed_app_user 相同的规则构建用户名
        name = f"authed-app-{bk_app_code}"

        # 查看数据库中是否存在该用户, 是否启用
        existing_client = SysAPIClient.objects.filter(name=name, is_active=True).first()
        if existing_client:
            raise error_codes.SYSAPI_CLIENT_ALREADY_EXISTS

        # 创建客户端
        client, created = SysAPIClient.objects.get_or_create(name=name, defaults={"role": role})
        if created:
            # 如果客户端是新创建的, 则创建应用认证关系
            AuthenticatedAppAsClient.objects.create(client=client, bk_app_code=bk_app_code)
        else:
            # 如果客户端已经存在, 则更新角色为启用状态
            client.is_active = True
            client.save(update_fields=["is_active"])

        # 构建审计数据
        after_data = [{"name": name, "bk_app_code": bk_app_code, "role": role}]

        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.CREATE,
            target=OperationTarget.PLAT_USER,
            data_after=DataDetail(type=DataType.RAW_DATA, data=after_data),
        )

        return Response(status=status.HTTP_201_CREATED)

    @atomic
    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="更新系统 API 用户的权限",
        request_body=UpsertSystemAPIUserSLZ,
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    def update(self, request, *args, **kwargs):
        slz = UpsertSystemAPIUserSLZ(data=request.data)
        slz.is_valid(raise_exception=True)
        data = slz.validated_data

        bk_app_code, role = data["bk_app_code"], data["role"]

        # 使用与管理命令 create_authed_app_user 相同的规则构建用户名
        name = f"authed-app-{bk_app_code}"

        # 检查要更新的用户是否存在, 并且是否启用
        client = SysAPIClient.objects.filter(name=name, is_active=True).first()
        if not client:
            raise error_codes.SYSAPI_CLIENT_NOT_FOUND

        # 构建审计数据
        before_data = [{"name": client.name, "bk_app_code": bk_app_code, "role": client.role}]

        # 更新角色
        if client.role != role:
            client.role = role
            client.save(update_fields=["role"])

        # 构建审计数据
        after_data = [{"name": name, "bk_app_code": bk_app_code, "role": role}]

        # 记录审计日志
        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.MODIFY,
            target=OperationTarget.PLAT_USER,
            data_before=DataDetail(type=DataType.RAW_DATA, data=before_data),
            data_after=DataDetail(type=DataType.RAW_DATA, data=after_data),
        )

        return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        tags=["plat_mgt.users"],
        operation_description="删除系统 API 用户",
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    @atomic
    def destroy(self, request, name=None, *args, **kwargs):
        """删除系统 API 用户, 后台对应逻辑为禁用用户"""
        client = SysAPIClient.objects.filter(name=name, is_active=True).first()
        if not client:
            raise error_codes.SYSAPI_CLIENT_NOT_FOUND

        # 构建审计数据
        app_client_relation = AuthenticatedAppAsClient.objects.filter(client=client).first()
        bk_app_code = app_client_relation.bk_app_code
        before_data = [{"name": client.name, "bk_app_code": bk_app_code, "role": client.role}]

        # 删除系统 API 用户, 仅仅禁用
        client.is_active = False
        client.save(update_fields=["is_active"])

        add_admin_audit_record(
            user=self.request.user.pk,
            operation=OperationEnum.DELETE,
            target=OperationTarget.PLAT_USER,
            data_before=DataDetail(type=DataType.RAW_DATA, data=before_data),
        )
        return Response(status=status.HTTP_204_NO_CONTENT)
