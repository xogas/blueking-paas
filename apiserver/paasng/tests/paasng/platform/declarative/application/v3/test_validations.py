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

from typing import Dict

import pytest

from paasng.accessories.publish.market.models import Tag
from paasng.platform.declarative.application.constants import CNATIVE_APP_CODE_FIELD
from paasng.platform.declarative.application.resources import ApplicationDesc, get_application
from paasng.platform.declarative.application.validations.v3 import AppDescriptionSLZ
from paasng.platform.declarative.exceptions import DescriptionValidationError
from paasng.platform.declarative.serializers import validate_desc
from tests.paasng.platform.declarative.utils import AppDescV3Builder as builder  # noqa: N813
from tests.paasng.platform.declarative.utils import AppDescV3Decorator as decorator  # noqa: N813
from tests.utils.basic import generate_random_string

pytestmark = pytest.mark.django_db(databases=["default", "workloads"])


@pytest.fixture(autouse=True)
def tag(bk_app):
    """A tag fixture for testing"""
    parent = Tag.objects.create(name="parent test")
    return Tag.objects.create(name="test", parent=parent)


def get_app_description(app_json: Dict) -> ApplicationDesc:
    """A help tool get parse the application json data, describe at app_desc.yml::app to ApplicationDesc"""
    instance = get_application(app_json, CNATIVE_APP_CODE_FIELD)
    desc = validate_desc(AppDescriptionSLZ, app_json, instance=instance)
    return desc


class TestValidateGoodCase:
    """A test suite about v3 validations - good case"""

    def test_one_module(self):
        # 保证应用 ID 是以字母开头
        bk_app_code = f"ut{generate_random_string(length=10)}"
        app_json = builder.make_app_desc(bk_app_code, decorator.with_module(module_name="foo", is_default=True))
        get_app_description(app_json)

    def test_normal_shared_addons(self):
        """测试单层服务依赖是允许的 - 模块A可以引用模块B的服务"""
        bk_app_code = f"ut{generate_random_string(length=10)}"

        # 创建一个有2个模块的应用，只有单层服务依赖
        app_json = builder.make_app_desc(
            bk_app_code,
            # 模块B：提供基础服务
            decorator.with_module(
                module_name="resource",
                is_default=False,
                module_spec={
                    "addons": [{"name": "mysql"}],  # 原始服务定义
                    "processes": [],
                },
            ),
            # 模块A：引用模块B的服务（单层依赖是允许的）
            decorator.with_module(
                module_name="frontend",
                is_default=True,
                module_spec={"addons": [{"name": "mysql", "sharedFromModule": "resource"}], "processes": []},
            ),
        )

        # 单层依赖应该可以成功通过校验
        desc = get_app_description(app_json)
        assert set(desc.modules) == {"frontend", "resource"}


class TestValidateBadCase:
    """A test suite about v3 validations - bad cases"""

    def test_invalid_name_length(self):
        # 保证应用 ID 是以字母开头
        bk_app_code = f"ut{generate_random_string(length=20)}"
        app_json = builder.make_app_desc(bk_app_code)
        with pytest.raises(DescriptionValidationError, match="bkAppCode: .*?20"):
            get_app_description(app_json)

    def test_missing_default_module(self):
        # 保证应用 ID 是以字母开头
        bk_app_code = f"ut{generate_random_string(length=10)}"
        app_json = builder.make_app_desc(bk_app_code, decorator.with_module(module_name="foo", is_default=False))
        with pytest.raises(DescriptionValidationError, match="modules"):
            get_app_description(app_json)

    def test_multiple_default_module(self):
        # 保证应用 ID 是以字母开头
        bk_app_code = f"ut{generate_random_string(length=10)}"
        app_json = builder.make_app_desc(
            bk_app_code,
            decorator.with_module(module_name="foo", is_default=True),
            decorator.with_module(module_name="bar", is_default=True),
        )
        with pytest.raises(DescriptionValidationError, match="modules"):
            get_app_description(app_json)

    def test_share_addon_error(self):
        bk_app_code = f"ut{generate_random_string(length=10)}"
        app_json = builder.make_app_desc(
            bk_app_code,
            decorator.with_module(
                module_name="foo",
                is_default=True,
                module_spec={"addons": [{"name": "openai", "sharedFromModule": "bar"}], "processes": []},
            ),
        )
        with pytest.raises(DescriptionValidationError, match="modules"):
            get_app_description(app_json)

    def test_nested_shared_addons(self):
        """测试多层服务依赖检查 - 不允许模块A引用模块B的服务，而模块B又引用模块C的服务"""
        bk_app_code = f"ut{generate_random_string(length=10)}"

        # 创建一个有3个模块的应用，形成多层服务依赖链
        app_json = builder.make_app_desc(
            bk_app_code,
            # 模块C：提供基础服务
            decorator.with_module(
                module_name="resource",
                is_default=False,
                module_spec={
                    "addons": [{"name": "mysql"}],  # 原始服务定义
                    "processes": [],
                },
            ),
            # 模块B：引用模块C的服务
            decorator.with_module(
                module_name="backend",
                is_default=False,
                module_spec={
                    "addons": [{"name": "mysql", "sharedFromModule": "resource"}],  # 第一次依赖
                    "processes": [],
                },
            ),
            # 模块A：引用模块B的服务，形成多层依赖
            decorator.with_module(
                module_name="frontend",
                is_default=True,
                module_spec={
                    "addons": [{"name": "mysql", "sharedFromModule": "backend"}],  # 第二次依赖，这里应该被拒绝
                    "processes": [],
                },
            ),
        )

        # 多层依赖应该会被拒绝
        with pytest.raises(DescriptionValidationError, match="modules"):
            get_app_description(app_json)

    @pytest.mark.parametrize(
        ("processes", "expected_error_keyword"),
        [
            (
                [
                    {
                        "name": "web",
                        "services": [{"name": "web", "targetPort": 5000, "exposedType": {"name": "cc/http"}}],
                    }
                ],
                r"不是合法选项",
            ),
            (
                [
                    {
                        "name": "web",
                        "services": [
                            {"name": "web", "targetPort": 5000, "exposedType": {"name": "bk/http"}},
                            {"name": "api", "targetPort": 5001, "exposedType": {"name": "bk/http"}},
                        ],
                    }
                ],
                r"duplicate exposedType: bk/http",
            ),
            (
                [
                    {
                        "name": "web",
                        "services": [
                            {"name": "web", "targetPort": 5000, "exposedType": {"name": "bk/http"}},
                        ],
                    },
                    {
                        "name": "api",
                        "services": [
                            {"name": "api", "targetPort": 5000, "exposedType": {"name": "bk/grpc"}},
                        ],
                    },
                ],
                r"setting multiple exposedTypes in an app module is not supported",
            ),
        ],
    )
    def test_proc_service_exposed_error(self, processes, expected_error_keyword):
        bk_app_code = f"ut{generate_random_string(length=10)}"
        app_json = builder.make_app_desc(
            bk_app_code,
            decorator.with_module(module_name="foo", is_default=True, module_spec={"processes": processes}),
        )
        with pytest.raises(DescriptionValidationError, match=expected_error_keyword):
            get_app_description(app_json)
