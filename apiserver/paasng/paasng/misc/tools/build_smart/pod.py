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
from dataclasses import dataclass, field
from typing import Any, Dict

from paas_wl.infras.resources.base.base import get_client_by_cluster_name
from paas_wl.infras.resources.base.exceptions import ResourceMissing
from paas_wl.infras.resources.base.kres import KPod
from paas_wl.utils.constants import PodPhase
from paasng.misc.tools.build_smart.models import SmartBuildRecord
from paasng.platform.engine.utils.output import get_default_stream

logger = logging.getLogger(__name__)


@dataclass
class SmartBuildSpec:
    """S-Mart package build spec

    Used to pass to smart-app-builder image when building smart package

    :param source_package_path: Path to the source package in the build Pod, use URL format
    :param dest_put_url: URL to upload the built package
    :param builder_shim_image: Builder shim image name
    :param cluster_name: Kubernetes cluster name where the Pod is built
    :param namespace: Namespace where the Pod is built
    :param builder_image: Builder image name used for building the smart package
    """

    source_package_path: str
    dest_put_url: str
    builder_shim_image: str
    cluster_name: str
    namespace: str
    builder_image: str

    privileged: bool = field(default=True)
    pod_name: str = field(default="builder")
    env_vars: Dict[str, str] = field(default_factory=dict)


class SmartBuildRunner:
    """Responsible for starting the s-smart package building task in k8s

    This class creates a Pod to execute the build,
    and monitors its status and log output in real time.

    :param build_id: build task ID, used for logging and identification
    :param spec: S-Mart build specification
    :param timeout: build timeout (in seconds)
    :param poll_interval: polling interval (in seconds)
    :param delete_pod_after_finish: whether to delete the Pod after the build completes
    """

    def __init__(
        self,
        smart_build: SmartBuildRecord,
        spec: SmartBuildSpec,
        timeout: int = 1800,
        poll_interval: float = 2.0,
        delete_pod_after_finish: bool = True,
    ):
        self.smart_build = smart_build
        self.spec = spec
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.delete_pod_after_finish = delete_pod_after_finish

        self.k8s = get_client_by_cluster_name(cluster_name=self.spec.cluster_name)
        self.pod_api = KPod(self.k8s)

        self.writer = get_default_stream(smart_build)

    def start(self) -> PodPhase:
        """Start the S-Mart package build

        Create and monitor the build pod,
        processing logs and status changes until the build completes or times out.
        Finally, clean up resources and update the build log.
        """

        result_status = PodPhase.RUNNING

        self.writer.write_title(f"Starting s-mart build: {self.smart_build.id}")
        self.writer.write_message(f"Using Cluster Name: {self.spec.cluster_name}")

        try:
            # Create/Reuse Pods
            manifest = self._build_manifest()
            self._ensure_pod(manifest)

            # Start monitoring Pod status
            result_status = self._monitor_pod_status()

        except Exception:
            logger.exception("Error during s-mart build")
        finally:
            # clean up resources
            self._cleanup_resource()

        return result_status

    def _build_manifest(self) -> Dict[str, Any]:
        """Generates the k8s resource definition for the build Pod

        :returns: Pod resource definition dictionary
        """

        container = {
            "name": "builder",
            "image": self.spec.builder_image,
            "env": [
                {"name": "SOURCE_GET_URL", "value": self.spec.source_package_path},
                {"name": "DEST_PUT_URL", "value": self.spec.dest_put_url},
                {"name": "BUILDER_SHIM_IMAGE", "value": self.spec.builder_shim_image},
            ],
            "securityContext": {"privileged": self.spec.privileged},
        }
        # TODO: 如果有 源码包 和 生成路径,添加卷挂载
        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": self.spec.pod_name,
                "namespace": self.spec.namespace,
                "labels": {
                    "app": "smart-app-builder",
                    "build-id": self.smart_build.id,
                },
            },
            "spec": {
                "containers": [container],
                "restartPolicy": "Never",
            },
        }
        return manifest

    def _ensure_pod(self, manifest: Dict[str, Any]):
        """Ensure the build Pod exists; if not, create it

        :param manifest: Pod resource definition
        """
        try:
            self.pod_api.get(name=self.spec.pod_name, namespace=self.spec.namespace)
            self.writer.write_message(f"Reuse existed pod: {self.spec.namespace}/{self.spec.pod_name}")
        except ResourceMissing:
            self.writer.write_message(f"Create new pod: {self.spec.namespace}/{self.spec.pod_name}")
            self.pod_api.create_or_update(self.spec.pod_name, namespace=self.spec.namespace, body=manifest)

    def _read_log_increment(self, sent_len: int) -> int:
        """Read and output the incremental portion of a Pod log

        :param sent_len: Length of the read log
        :returns: Total length of the new log
        """
        try:
            stream = self.pod_api.get_log(self.spec.pod_name, namespace=self.spec.namespace, timeout=8)
            raw = stream.read().decode(errors="ignore")
        except Exception as e:
            logger.debug("fetch build logs failed: %s", e)
            return sent_len

        if len(raw) <= sent_len:
            return sent_len

        # Process new logs
        for line in raw[sent_len:].rstrip().splitlines():
            if line.strip():
                self.writer.write_message(line)

        return len(raw)

    def _monitor_pod_status(self) -> PodPhase:
        """Monitors the Pod status until it completes or times out.

        :returns: Final Pod status.
        """
        start_ts = time.time()
        deadline = start_ts + self.timeout
        sent_len = 0
        phase = PodPhase.RUNNING

        while True:
            # Check timeout
            current_time = time.time()
            if current_time > deadline:
                self.writer.write_message(
                    f"Build timeout: {int(current_time - start_ts)} seconds",
                    stream="STDERR",
                )
                return PodPhase.FAILED

            # Get Pod Status
            try:
                pod_obj = self.pod_api.get(self.spec.pod_name, namespace=self.spec.namespace)
            except ResourceMissing:
                self.writer.write_message(
                    f"Pod {self.spec.namespace}/{self.spec.pod_name} does not exist, waiting to be created...",
                    stream="STDERR",
                )
                time.sleep(self.poll_interval)
                continue

            # Handling state changes
            # FIXME: 可能需要修复该获取方式?
            new_phase_raw = getattr(pod_obj.status, "phase", "")
            new_phase = phase
            if isinstance(new_phase_raw, str) and new_phase_raw:
                try:
                    new_phase = PodPhase(new_phase_raw)
                except Exception:
                    logger.debug("Unknown pod phase value: %s", new_phase_raw)
            elif isinstance(new_phase_raw, PodPhase):
                new_phase = new_phase_raw

            if new_phase != phase:
                phase = new_phase

            # Read log increments
            sent_len = self._read_log_increment(sent_len)

            # # Check whether completed
            if phase in {PodPhase.SUCCEEDED, PodPhase.FAILED}:
                break

            time.sleep(self.poll_interval)

        return phase

    def _cleanup_resource(self) -> None:
        """Cleaning build resources"""
        if self.delete_pod_after_finish:
            try:
                self.pod_api.delete(self.spec.pod_name, namespace=self.spec.namespace)
                self.writer.write_message(f"Pod {self.spec.namespace}/{self.spec.pod_name} deleted successfully")
            except Exception as e:
                logger.debug("delete pod failed: %s", e)
                self.writer.write_message(
                    f"Failed to delete Pod {self.spec.namespace}/{self.spec.pod_name}: {e}", stream="STDERR"
                )
