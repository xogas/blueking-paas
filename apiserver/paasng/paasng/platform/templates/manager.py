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
from operator import attrgetter
from typing import Dict, List, Optional

from paasng.platform.engine.constants import RuntimeType
from paasng.platform.modules.entities import BuildConfig
from paasng.platform.modules.models import AppBuildPack, AppSlugBuilder
from paasng.platform.modules.models.build_cfg import ImageTagOptions
from paasng.platform.templates.models import Template

logger = logging.getLogger(__name__)


class TemplateRuntimeManager:
    """模板的运行时管理器

    :param tmpl_name: 模板名称，通常为 dj2_with_examples 之类的代号。
    """

    def __init__(self, tmpl_name: str):
        self.template = Template.objects.get(name=tmpl_name)

    def get_preset_services_config(self) -> Dict[str, Dict]:
        """获取预设增强服务配置"""
        return self.template.preset_services_config

    def get_docker_build_config(self) -> BuildConfig:
        """获取 Docker 构建配置"""
        # TODO: 在支持 Dockerfile 类型的模板时，重新提供合理的实现
        return BuildConfig(
            build_method=RuntimeType.DOCKERFILE,
            dockerfile_path="Dockerfile",
            docker_build_args={},
            tag_options=ImageTagOptions(),
        )

    def get_required_buildpacks(self, bp_stack_name: str) -> List[AppBuildPack]:
        """获取构建模板代码需要的构建工具"""
        try:
            required_buildpacks = self.get_template_required_buildpacks(bp_stack_name=bp_stack_name)
        except Template.DoesNotExist:
            required_buildpacks = []
        language_bp = self.get_language_buildpack(bp_stack_name=bp_stack_name)
        if language_bp:
            required_buildpacks.append(language_bp)
        return required_buildpacks

    def get_template_required_buildpacks(self, bp_stack_name: str) -> List[AppBuildPack]:
        """获取模板声明的需要依赖的构建工具"""
        required_buildpacks = self.template.required_buildpacks
        if isinstance(required_buildpacks, list):
            bp_names = required_buildpacks
        elif isinstance(required_buildpacks, dict):
            if stack_required_buildpacks := required_buildpacks.get(bp_stack_name):
                bp_names = stack_required_buildpacks
            else:
                bp_names = required_buildpacks.get("__default__") or []
        else:
            raise TypeError("required_buildpacks is invalid")

        builder = AppSlugBuilder.objects.get(name=bp_stack_name)
        available_bps = {bp.name: bp for bp in builder.list_available_buildpacks(name__in=bp_names)}

        if missing_bps := available_bps.keys() - set(bp_names):
            raise RuntimeError("No buildpacks can be found for name: {}".format(missing_bps))

        return [available_bps[bp_name] for bp_name in bp_names]

    def get_language_buildpack(self, bp_stack_name: str) -> Optional[AppBuildPack]:
        """获取和模块(或模板)语言相关的构建工具"""
        builder = AppSlugBuilder.objects.get(name=bp_stack_name)
        buildpacks = builder.list_available_buildpacks(language=self.template.language)
        if not buildpacks:
            return None
        # 选取指定语言的最新一个非隐藏的 buildpack
        buildpack = sorted(buildpacks, key=attrgetter("created"))[-1]
        return buildpack
