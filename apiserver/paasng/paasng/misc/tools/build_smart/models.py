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

import uuid

from django.db import models

from paasng.misc.tools.build_smart.task import SourceCodeOriginType
from paasng.utils.models import BkUserField


class SmartBuildRecord(models.Model):
    """s-mart 包构建记录"""

    id = models.UUIDField("UUID", default=uuid.uuid4, primary_key=True, editable=False, auto_created=True, unique=True)
    source_origin = models.CharField(max_length=32, choices=SourceCodeOriginType.get_choices())
    branch = models.CharField(max_length=128, blank=True, default="")
    package_name = models.CharField(max_length=256, blank=True, default="")
    artifact_url = models.TextField(blank=True, default="")
    status = models.CharField(max_length=32)
    time_spent = models.IntegerField(null=True)

    operator = BkUserField()

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
