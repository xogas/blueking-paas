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
import time
from os import PathLike
from pathlib import Path
from typing import Optional

from blue_krill.data_types.enum import EnumField, StrStructuredEnum
from django.utils.translation import gettext as _

from paas_wl.utils.constants import BuildStatus
from paasng.misc.tools.build_smart.models import SmartBuildRecord
from paasng.platform.declarative.exceptions import DescriptionValidationError
from paasng.platform.smart_app.services.app_desc import get_app_description
from paasng.platform.smart_app.services.detector import SourcePackageStatReader

from .output import get_default_stream
from .pod import SmartBuildSpec

logger = logging.getLogger(__name__)


class SourceCodeOriginType(StrStructuredEnum):
    """源代码来源类型"""

    PACKAGE = EnumField("package", label=_("源码包"))
    REPO = EnumField("repo", label=_("代码仓库"))


class BuildPhaseTypes(StrStructuredEnum):
    """构建阶段"""

    PREPARATION = EnumField("preparation", label=_("准备阶段"))
    BUILD = EnumField("build", label=_("构建阶段"))


def initialize_smart_build_record(
    package_path: PathLike,
    operator: str,
) -> SmartBuildRecord:
    """Initialize s-smart package build record

    :param package_path: Path to the source package file
    :param operator: The user ID of the operator
    """

    # TODO: Support source code repository locally and obtaining the branch
    source_origin = SourceCodeOriginType.PACKAGE.value
    branch = ""
    package_name = Path(package_path).name
    status = BuildStatus.PENDING.value

    record = SmartBuildRecord.objects.create(
        source_origin=source_origin,
        branch=branch,
        package_name=package_name,
        status=status,
        operator=operator,
    )
    record.refresh_from_db()
    return record


class SmartBuildTaskRunner:
    """Start a s-mart build task

    Coordinate the build process, including verification, building, and launching
    """

    def __init__(self, smart_build: SmartBuildRecord, source_package_path: PathLike):
        self.smart_build = smart_build
        self.source_package_path = Path(source_package_path).resolve().as_uri()
        self.start_time = time.time()
        self.writer = get_default_stream(smart_build)
        self.spec: Optional[SmartBuildSpec] = None

        # TODO: 获取集群名, 命名空间, 构建镜像

    def start(self):
        """Start a s-mart build task"""

        self.update_smart_build_record(BuildStatus.PENDING.value)

        try:
            # Start preparation phase
            self.start_preparation_phase()

            # Start build phase
            self.start_build_phase()

            # Update build record
            self.update_smart_build_record(BuildStatus.SUCCESSFUL.value)

        except Exception as e:
            self._handler_exception(e)
        finally:
            self.writer.close()

    def start_preparation_phase(self):
        """Run the preparation phase step"""
        self.writer.write_event("phase", {"name": "preparation", "status": "started"})

        try:
            # Validate app_desc file
            self._validate_app_desc()

            # Verify file and directory structure in the source
            self._verify_file_dir()

            # Scan sensitive information
            self._scan_sensitive_information()
        finally:
            self.writer.write_event("phase", {"name": "preparation", "status": "completed"})

    def start_build_phase(self):
        """Run the build phase step"""
        self.writer.write_event("phase", {"name": "build", "status": "started"})

        try:
            # Initialize the build spec
            self._init_build_spec()

            # Analyzing build plan
            self._analyze_build_plan()

            # Check build tools
            self._check_build_tools()

            # Run build process
            self._run_smart_build_process()

        finally:
            self.writer.write_event("phase", {"name": "build", "status": "completed"})

    def update_smart_build_record(self, status: BuildStatus):
        """Update s-mart build record"""
        time_spent = int(time.time() - self.start_time)

        if status == BuildStatus.SUCCESSFUL.value and self.spec is not None:
            self.smart_build.artifact_url = self.spec.dest_put_url

        self.smart_build.status = status
        self.smart_build.time_spent = time_spent
        self.smart_build.save()

    def _validate_app_desc(self):
        # TODO 增加一些前置校验, 确保 app_desc 符合构建要求
        stat = SourcePackageStatReader(Path(self.source_package_path)).read()
        app_desc = get_app_description(stat)
        if app_desc.market is None:
            raise DescriptionValidationError({"market": "内容不能为空"})

    def _verify_file_dir(self):
        """Verify the source package file directory"""
        # 使用 self.source_package_path, 是 url 格式

    def _scan_sensitive_information(self):
        """Scan sensitive information, Only the cloud version is checked

        Need to call codecc API
        """

    def _init_build_spec(self):
        """Build SmartBuildSpec object"""

    def _analyze_build_plan(self):
        """Analyze build plan"""

    def _check_build_tools(self):
        """Check build tools"""

    def _run_smart_build_process(self):
        """Building the s-mart package in k8s"""

    def _handler_exception(self, e: Exception):
        """Handler Exception"""
