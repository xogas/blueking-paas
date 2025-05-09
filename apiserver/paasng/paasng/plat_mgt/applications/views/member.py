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


from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status, viewsets
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from paasng.infras.accounts.permissions.constants import PlatMgtAction
from paasng.infras.accounts.permissions.plat_mgt import plat_mgt_perm_class
from paasng.infras.iam.exceptions import BKIAMGatewayServiceError
from paasng.infras.iam.helpers import (
    fetch_application_members,
    fetch_user_roles,
    remove_user_all_roles,
)
from paasng.misc.audit import constants
from paasng.misc.audit.service import DataDetail, add_admin_audit_record
from paasng.plat_mgt.applications import serializers as slzs
from paasng.platform.applications.constants import ApplicationRole
from paasng.platform.applications.models import Application, ApplicationMembership
from paasng.platform.applications.signals import application_member_updated
from paasng.platform.applications.tasks import sync_developers_to_sentry
from paasng.utils.error_codes import error_codes


class ApplicationMemberViewSet(viewsets.GenericViewSet):
    """平台管理 - 应用成员管理 API"""

    queryset = ApplicationMembership.objects.all()
    permission_classes = [IsAuthenticated, plat_mgt_perm_class(PlatMgtAction.ALL)]
    pagination_class = LimitOffsetPagination

    @staticmethod
    def _gen_data_detail(code: str, username: str) -> DataDetail:
        return DataDetail(
            type=constants.DataType.RAW_DATA,
            data={
                "username": username,
                "roles": [ApplicationRole(role).name.lower() for role in fetch_user_roles(code, username)],
            },
        )

    @swagger_auto_schema(
        tags=["plat_mgt.applications.members"],
        responses={status.HTTP_200_OK: slzs.ApplicationMembershipSLZ(many=True)},
    )
    def list(self, request, *args, **kwargs):
        """获取指定应用的成员列表"""
        application = get_object_or_404(Application, code=kwargs["app_code"])
        members = fetch_application_members(application.code)
        slz = slzs.ApplicationMembershipSLZ(members, many=True)
        return Response(data=slz.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        """添加成员"""
        # application = get_object_or_404(Application, code=kwargs["app_code"])
        # slz = slzs.ApplicationMembershipSLZ(data=request.data, many=True)
        # slz.is_valid(raise_exception=True)

        # data_before = []
        # for item in slz.validated_data:
        #     username = item["username"]
        #     role = ApplicationRole(item["role"])
        #     data_before.append(self._gen_data_detail(application.code, username))

        #     try:
        #         add_role_members(application.code, role, username)
        #     except BKIAMGatewayServiceError as e:
        #         raise e.message

        # for item in slz.validated_data:
        #     add_admin_audit_record(
        #         user=request.user.pk,
        #         operation=constants.OperationEnum.CREATE,
        #         target=constants.OperationTarget.APP_MEMBER,
        #         app_code=application.code,
        #         data_before=data_before,
        #         data_after=self._gen_data_detail(application.code, item["username"]),
        #     )

        # self.sync_membership(application)
        # return Response(status=status.HTTP_201_CREATED)

    @swagger_auto_schema(
        tags=["plat_mgt.applications.members"],
        request_body=slzs.ApplicationMembershipSLZ,
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    def update(self, request, *args, **kwargs):
        """更新成员"""
        # code = kwargs["app_code"]
        # role, username = request.data["role"], request.data["username"]
        # application = get_object_or_404(Application, code=code)
        # data_before = self._gen_data_detail(application.code, username)

        # try:
        #     remove_user_all_roles(application.code, username)
        #     add_role_members(application.code, ApplicationRole(role), username)
        # except BKIAMGatewayServiceError as e:
        #     raise error_codes.UPDATE_APP_MEMBERS_ERROR.f(e.message)

        # add_admin_audit_record(
        #     user=request.user.pk,
        #     operation=constants.OperationEnum.MODIFY,
        #     target=constants.OperationTarget.APP_MEMBER,
        #     app_code=code,
        #     data_before=data_before,
        #     data_after=self._gen_data_detail(application.code, username),
        # )

        # self.sync_membership(application)
        # return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        tags=["plat_mgt.applications.members"],
        responses={status.HTTP_204_NO_CONTENT: None},
    )
    def destroy(self, request, *args, **kwargs):
        """删除成员"""
        code, username = kwargs["app_code"], kwargs["username"]
        application = get_object_or_404(Application, code=code)
        data_before = self._gen_data_detail(application.code, username)

        try:
            remove_user_all_roles(application.code, username)
        except BKIAMGatewayServiceError as e:
            raise error_codes.DELETE_APP_MEMBERS_ERROR.f(e.message)

        add_admin_audit_record(
            user=request.user.pk,
            operation=constants.OperationEnum.DELETE,
            target=constants.OperationTarget.APP_MEMBER,
            app_code=code,
            data_before=data_before,
            data_after=self._gen_data_detail(application.code, username),
        )

        self.sync_membership(application)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @swagger_auto_schema(
        tags=["plat_mgt.applications.members"],
        responses={status.HTTP_200_OK: slzs.PermissionModelOutputSLZ(many=True)},
    )
    def view_permission_model(self, request, *args, **kwargs):
        """查看权限模型"""

        data = []
        excluded_roles = {"NOBODY", "COLLABORATOR", "_choices_labels"}
        for role in ApplicationRole:
            if role.name in excluded_roles:
                continue
            data.append({"name": role.name.lower()})
        slz = slzs.PermissionModelOutputSLZ(data, many=True)
        return Response(data=slz.data, status=status.HTTP_200_OK)

    def sync_membership(self, application):
        sync_developers_to_sentry.delay(application.id)
        application_member_updated.send(sender=application, application=application)
