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

from blue_krill.data_types.enum import EnumField, StrStructuredEnum

# 为方便用户填写而设计的端口占位符, 并非实际的 shell 环境变量. 在转换成 BkApp 模型时会被平台替换成预设值 settings.CONTAINER_PORT
PORT_PLACEHOLDER = "${PORT}"


class ExposedTypeName(StrStructuredEnum):
    """与 paas_wl.workloads.networking.constants.ExposedTypeName 重复定义
    # TODO 将 paasng 和 paas_wl 中重复定义的一些常量, 合并放到更底层的模块中, 避免破坏当前 importlinter 的依赖规则?
    """

    BK_HTTP = "bk/http"
    BK_GRPC = "bk/grpc"


class NetworkProtocol(StrStructuredEnum):
    """与 paas_wl.workloads.networking.constants.NetworkProtocol 重复定义
    # TODO 将 paasng 和 paas_wl 中重复定义的一些常量, 合并放到更底层的模块中, 避免破坏当前 importlinter 的依赖规则?
    """

    TCP = EnumField("TCP", label="TCP")
    UDP = EnumField("UDP", label="UDP")


class ImagePullPolicy(StrStructuredEnum):
    """duplicated from paas_wl.workloads.release_controller.constants.ImagePullPolicy to decouple dependencies
    TODO 统一放置到一个独立于 paas_wl 和 paasng 的模块下?
    """

    ALWAYS = EnumField("Always")
    IF_NOT_PRESENT = EnumField("IfNotPresent")
    NEVER = EnumField("Never")


class ResQuotaPlan(StrStructuredEnum):
    """duplicated from paas_wl.bk_app.cnative.specs.constants.ResQuotaPlan to decouple dependencies
    TODO 统一放置到一个独立于 paas_wl 和 paasng 的模块下?
    """

    P_DEFAULT = EnumField("default", label="default")
    P_4C1G = EnumField("4C1G", label="4C1G")
    P_4C2G = EnumField("4C2G", label="4C2G")
    P_4C4G = EnumField("4C4G", label="4C4G")


def parse_res_quota_plan(plan: str) -> tuple[str, str] | None:
    """解析资源配额方案，返回 (cpu, memory) 元组"""
    import re

    from kubernetes.utils import parse_quantity

    # 预定义方案映射
    predefined_plans = {
        "default": ("4000m", "1024Mi"),
        "4C1G": ("4000m", "1024Mi"),
        "4C2G": ("4000m", "2048Mi"),
        "4C4G": ("4000m", "4096Mi"),
    }

    if plan in predefined_plans:
        return predefined_plans[plan]

    # 解析自定义格式：{CPU}C{Memory}
    # 匹配格式如：2C400Mi、4C1G、0.5C512Mi
    pattern = r"^([1-9]\d*(?:\.\d+)?|0\.\d+)C([1-9]\d*(?:\.\d+)?|0\.\d+)(M|Mi|G|Gi)$"
    match = re.match(pattern, plan, re.IGNORECASE)

    if not match:
        return None

    cpu_cores = match.group(1)
    memory = match.group(2)

    try:
        # 验证 CPU 值的有效性（转换为 millicores）
        cpu_float = float(cpu_cores)
        if cpu_float <= 0:
            return None
        cpu_str = f"{int(cpu_float * 1000)}m"

        # 验证 Memory 值的有效性（使用 kubernetes 的 parse_quantity）
        try:
            mem_quantity = parse_quantity(memory)
            if mem_quantity <= 0:
                return None
        except (ValueError, Exception):
            return None

        return (cpu_str, memory)
    except (ValueError, Exception):
        return None


def is_available_res_quota_plan(plan: str) -> bool:
    """检查 plan 是否有效

    :param plan: 资源配额方案字符串
    :return: 是否有效
    """
    if not plan:
        return False

    result = parse_res_quota_plan(plan)
    return result is not None


class ScalingPolicy(StrStructuredEnum):
    """duplicated from paas_wl.bk_app.cnative.specs.constants.ScalingPolicy to decouple dependencies
    TODO 统一放置到一个独立于 paas_wl 和 paasng 的模块下?
    """

    # the default autoscaling policy (cpu utilization 85%)
    DEFAULT = EnumField("default")
