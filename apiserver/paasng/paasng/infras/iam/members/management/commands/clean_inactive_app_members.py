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


import json
import traceback

from django.conf import settings
from django.core.management.base import BaseCommand

from paasng.infras.iam.helpers import delete_role_members, fetch_application_members, fetch_role_members
from paasng.platform.applications.constants import ApplicationRole, ApplicationType
from paasng.platform.applications.models import Application
from paasng.platform.evaluation.providers import StaffStatusProvider


class Command(BaseCommand):
    """清理应用成员中的已离职人员

    使用示例
    python manage.py clean_inactive_app_members                             # 清理全量数据
    python manage.py clean_inactive_app_members --dry-run                   # 仅打印待清理清单
    python manage.py clean_inactive_app_members --apps app_code1 app_code2  # 清理指定应用的数据
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run", dest="dry_run", action="store_true", default=False, help="不真正执行, 仅打印待清理数据"
        )
        parser.add_argument("--apps", nargs="*", help="仅处理指定应用 code 列表, 不指定则全量处理")

    def handle(self, dry_run, apps, *args, **options):
        self.dry_run: bool = dry_run
        # 平台管理员永远不被清理
        self.platform_managers: set[str] = set(settings.BKPAAS_PLATFORM_MANAGERS)
        self.provider = StaffStatusProvider()

        self.success_records: list[dict] = []
        self.failed_records: list[dict] = []
        self.skipped_records: list[dict] = []

        # 1. 扫描应用并执行清理
        applications = Application.objects.filter(is_active=True).exclude(type=ApplicationType.ENGINELESS_APP)
        if apps:
            applications = applications.filter(code__in=apps)

        self.total = applications.count()
        self.stdout.write(f"---------------- start scanning {self.total} applications ----------------")
        if self.dry_run:
            self.stdout.write("------------------------- DRY-RUN -------------------------")

        for idx, app in enumerate(applications, start=1):
            try:
                self._process_single_app(idx, app)
            except Exception as e:  # noqa: BLE001
                self.failed_records.append(
                    {
                        "idx": idx,
                        "app_code": app.code,
                        "exception": str(e),
                        "traceback": traceback.format_exc(),
                    }
                )
                self.stderr.write(f"{idx}/{self.total} app {app.code} failed: {e}")

        self.stdout.write("---------------- scan finished ----------------")
        self.stdout.write(
            f"-- success: {len(self.success_records)} failed: {len(self.failed_records)} skipped: {len(self.skipped_records)} --",
        )

        # 2. 输出审计文件
        suffix = "dry_run" if self.dry_run else "real"
        for filepath, records in [
            (f"/tmp/clean_inactive_members_success_{suffix}.json", self.success_records),
            (f"/tmp/clean_inactive_members_failed_{suffix}.json", self.failed_records),
            (f"/tmp/clean_inactive_members_skipped_{suffix}.json", self.skipped_records),
        ]:
            with open(filepath, "w") as fw:
                fw.write(json.dumps(records, indent=4, ensure_ascii=False))
            self.stdout.write(f"  -> {filepath} ({len(records)} records)")

    def _process_single_app(self, idx: int, app: Application):
        """处理单个应用, 识别离职成员并按角色清理"""
        # member: {"username": str, "roles": [int], "user": str}
        members = fetch_application_members(app.code)
        if not members:
            return

        # 按角色聚合待清理用户名
        inactive_by_role: dict[int, list[str]] = {}
        all_inactive: set[str] = set()

        for m in members:
            username = m["username"]
            if username in self.platform_managers:
                continue
            if self.provider.is_active(username):
                continue

            all_inactive.add(username)
            for role in m["roles"]:
                inactive_by_role.setdefault(role, []).append(username)

        if not all_inactive:
            return

        # 清理后该应用必须仍有在职管理员, 否则跳过 + 告警
        admins = fetch_role_members(app.code, ApplicationRole.ADMINISTRATOR)
        remaining_active_admins = [
            u for u in admins if u not in all_inactive and (u in self.platform_managers or self.provider.is_active(u))
        ]
        if not remaining_active_admins:
            self.skipped_records.append(
                {
                    "idx": idx,
                    "app_code": app.code,
                    "reason": "no_active_administrator_after_cleanup",
                    "inactive_by_role": {
                        ApplicationRole(role).name: usernames for role, usernames in inactive_by_role.items()
                    },
                }
            )
            self.stdout.write(
                f"{idx}/{self.total} app {app.code} skipped: "
                f"no active administrator would remain. inactive={sorted(all_inactive)}"
            )
            return

        # 执行清理 (dry-run 只记录)
        logs = [f"app_code={app.code}, inactive_users={sorted(all_inactive)}"]
        for role, usernames in inactive_by_role.items():
            role_name = ApplicationRole(role).name
            logs.append(f"role={role_name} remove={usernames}")
            if self.dry_run:
                continue
            # delete_role_members 内部会处理: 若 role 是 ADMINISTRATOR, 同时移除分级管理员身份
            delete_role_members(app.code, ApplicationRole(role), usernames)

        self.success_records.append(
            {
                "idx": idx,
                "app_code": app.code,
                "inactive_by_role": {
                    ApplicationRole(role).name: usernames for role, usernames in inactive_by_role.items()
                },
                "logs": logs,
            }
        )
        flag = "?" if self.dry_run else "."
        action = "would clean" if self.dry_run else "cleaned"
        self.stdout.write(f"{flag} {idx}/{self.total} app {app.code} {action} {len(all_inactive)} inactiveew user(s)")
