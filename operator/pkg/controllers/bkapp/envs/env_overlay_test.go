/*
 * TencentBlueKing is pleased to support the open source community by making
 * 蓝鲸智云 - PaaS 平台 (BlueKing - PaaS System) available.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
 * Licensed under the MIT License (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 *	http://opensource.org/licenses/MIT
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * We undertake not to change the open source license (MIT license) applicable
 * to the current version of the project delivered to anyone in the future.
 */

package envs

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	paasv1alpha1 "bk.tencent.com/paas-app-operator/api/v1alpha1"
	paasv1alpha2 "bk.tencent.com/paas-app-operator/api/v1alpha2"
	"bk.tencent.com/paas-app-operator/pkg/config"
	"bk.tencent.com/paas-app-operator/pkg/kubeutil"
)

var _ = Describe("Environment overlay related functions", func() {
	var bkapp *paasv1alpha2.BkApp
	var builder *fake.ClientBuilder
	var scheme *runtime.Scheme

	BeforeEach(func() {
		bkapp = &paasv1alpha2.BkApp{
			TypeMeta: metav1.TypeMeta{
				Kind:       paasv1alpha2.KindBkApp,
				APIVersion: paasv1alpha2.GroupVersion.String(),
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      "bkapp-sample",
				Namespace: "default",
			},
			Spec: paasv1alpha2.AppSpec{
				Build: paasv1alpha2.BuildConfig{
					Image: "nginx:latest",
				},
				Processes: []paasv1alpha2.Process{
					{
						Name:         "web",
						Replicas:     paasv1alpha2.ReplicasTwo,
						ResQuotaPlan: paasv1alpha2.ResQuotaPlanDefault,
						TargetPort:   80,
						Autoscaling: &paasv1alpha2.AutoscalingSpec{
							MinReplicas: 1,
							MaxReplicas: 5,
							Policy:      paasv1alpha2.ScalingPolicyDefault,
						},
					},
					{
						Name:         "worker",
						Replicas:     paasv1alpha2.ReplicasTwo,
						ResQuotaPlan: paasv1alpha2.ResQuotaPlanDefault,
						Autoscaling: &paasv1alpha2.AutoscalingSpec{
							MinReplicas: 2,
							MaxReplicas: 6,
							Policy:      paasv1alpha2.ScalingPolicyDefault,
						},
					},
				},
				Configuration: paasv1alpha2.AppConfig{
					Env: []paasv1alpha2.AppEnvVar{
						{Name: "ENV_1", Value: "value_1"},
						{Name: "ENV_2", Value: "value_2"},
					},
				},
			},
		}

		builder = fake.NewClientBuilder()
		scheme = runtime.NewScheme()
		Expect(paasv1alpha2.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(corev1.AddToScheme(scheme)).NotTo(HaveOccurred())
		builder.WithScheme(scheme)
	})

	Context("Test GetEnvName", func() {
		It("missing", func() {
			envName := GetEnvName(bkapp)
			Expect(envName.IsEmpty()).To(BeTrue())
		})
		It("invalid value", func() {
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "invalid-env"})
			envName := GetEnvName(bkapp)
			Expect(envName.IsEmpty()).To(BeTrue())
		})
		It("normal", func() {
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "stag"})
			envName := GetEnvName(bkapp)
			Expect(envName.IsEmpty()).To(BeFalse())
			Expect(envName).To(Equal(paasv1alpha2.StagEnv))
		})
	})

	Context("Test ReplicasGetter without env", func() {
		It("process normal", func() {
			val := NewReplicasGetter(bkapp).GetByProc("web")
			Expect(*val).To(Equal(int32(2)))
		})
		It("process missing", func() {
			val := NewReplicasGetter(bkapp).GetByProc("web-missing")
			Expect(val).To(BeNil())
		})
	})

	Context("Test ReplicasGetter with env", func() {
		BeforeEach(func() {
			// Set up application to add env overlay related info
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "stag"})
			bkapp.Spec.EnvOverlay = &paasv1alpha2.AppEnvOverlay{
				Replicas: []paasv1alpha2.ReplicasOverlay{
					{EnvName: "stag", Process: "web", Count: 10},
					{EnvName: "prod", Process: "web", Count: 20},
				},
			}
		})
		It("env overlay hit", func() {
			val := NewReplicasGetter(bkapp).GetByProc("web")
			Expect(*val).To(Equal(int32(10)))
		})
		It("env overlay absent", func() {
			val := NewReplicasGetter(bkapp).GetByProc("worker")
			Expect(*val).To(Equal(int32(2)))
		})
	})

	Context("Test EnvVarsGetter without env", func() {
		It("normal", func() {
			vars := NewEnvVarsGetter(bkapp).Get()
			Expect(vars).To(Equal([]corev1.EnvVar{
				{Name: "ENV_1", Value: "value_1"},
				{Name: "ENV_2", Value: "value_2"},
			}))
		})
	})

	Context("Test EnvVarsGetter with env", func() {
		BeforeEach(func() {
			// Set up application to add env overlay related info
			bkapp.Spec.EnvOverlay = &paasv1alpha2.AppEnvOverlay{
				EnvVariables: []paasv1alpha2.EnvVarOverlay{
					{EnvName: "stag", Name: "ENV_3", Value: "value_3"},
					{EnvName: "prod", Name: "ENV_4", Value: "value_4"},
					{EnvName: "stag", Name: "ENV_2", Value: "value_new_2"},
				},
			}
		})
		It("stag env", func() {
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "stag"})
			vars := NewEnvVarsGetter(bkapp).Get()
			Expect(vars).To(Equal([]corev1.EnvVar{
				{Name: "ENV_1", Value: "value_1"},
				{Name: "ENV_2", Value: "value_new_2"},
				{Name: "ENV_3", Value: "value_3"},
			}))
		})
		It("prod env", func() {
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "prod"})
			vars := NewEnvVarsGetter(bkapp).Get()
			Expect(vars).To(Equal([]corev1.EnvVar{
				{Name: "ENV_1", Value: "value_1"},
				{Name: "ENV_2", Value: "value_2"},
				{Name: "ENV_4", Value: "value_4"},
			}))
		})
	})

	Context("Test AutoscalingPolicyGetter without env", func() {
		It("process normal", func() {
			spec := NewAutoscalingSpecGetter(bkapp).GetByProc("web")
			Expect(spec.MinReplicas).To(Equal(int32(1)))
			Expect(spec.MaxReplicas).To(Equal(int32(5)))
			Expect(spec.Policy).To(Equal(paasv1alpha2.ScalingPolicyDefault))
		})
		It("process missing", func() {
			spec := NewAutoscalingSpecGetter(bkapp).GetByProc("web-missing")
			Expect(spec).To(BeNil())
		})
	})

	Context("Test AutoscalingPolicyGetter with env", func() {
		BeforeEach(func() {
			// Set up application to add env overlay related info
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "stag"})
			bkapp.Spec.EnvOverlay = &paasv1alpha2.AppEnvOverlay{
				Autoscaling: []paasv1alpha2.AutoscalingOverlay{
					{
						EnvName: "stag",
						Process: "web",
						AutoscalingSpec: paasv1alpha2.AutoscalingSpec{
							MinReplicas: 2, MaxReplicas: 5, Policy: "custom",
						},
					},
				},
			}
		})
		It("env overlay hit", func() {
			spec := NewAutoscalingSpecGetter(bkapp).GetByProc("web")
			Expect(spec.MinReplicas).To(Equal(int32(2)))
			Expect(spec.MaxReplicas).To(Equal(int32(5)))
			Expect(spec.Policy).To(Equal(paasv1alpha2.ScalingPolicy("custom")))
		})
		It("env overlay absent", func() {
			spec := NewAutoscalingSpecGetter(bkapp).GetByProc("worker")
			Expect(spec.MinReplicas).To(Equal(int32(2)))
			Expect(spec.MaxReplicas).To(Equal(int32(6)))
			Expect(spec.Policy).To(Equal(paasv1alpha2.ScalingPolicyDefault))
		})
	})

	Context("Test ProcResourcesGetter", func() {
		It("Get Default", func() {
			resReq := NewProcResourcesGetter(bkapp).Default()
			Expect(resReq.Requests.Cpu().Equal(resource.MustParse("200m"))).To(BeTrue())
			Expect(resReq.Requests.Memory().Equal(resource.MustParse("256Mi"))).To(BeTrue())
			Expect(resReq.Limits.Cpu().Equal(resource.MustParse("4"))).To(BeTrue())
			Expect(resReq.Limits.Memory().Equal(resource.MustParse("1024Mi"))).To(BeTrue())
		})

		It("Get Legacy", func() {
			_ = kubeutil.SetJsonAnnotation(
				bkapp, paasv1alpha2.LegacyProcResAnnoKey, paasv1alpha2.LegacyProcConfig{
					"web": {"cpu": "2", "memory": "2Gi"},
				},
			)
			getter := NewProcResourcesGetter(bkapp)
			resReq, _ := getter.GetByProc("web")
			Expect(resReq.Requests.Cpu().Equal(resource.MustParse("200m"))).To(BeTrue())
			Expect(resReq.Requests.Memory().Equal(resource.MustParse("1Gi"))).To(BeTrue())
			Expect(resReq.Limits.Cpu().Equal(resource.MustParse("2"))).To(BeTrue())
			Expect(resReq.Limits.Memory().Equal(resource.MustParse("2Gi"))).To(BeTrue())
		})

		It("Get Overlay", func() {
			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "stag"})
			bkapp.Spec.EnvOverlay = &paasv1alpha2.AppEnvOverlay{
				ResQuotas: []paasv1alpha2.ResQuotaOverlay{
					{EnvName: "stag", Process: "web", Plan: paasv1alpha2.ResQuotaPlan4C1G},
				},
			}
			getter := NewProcResourcesGetter(bkapp)

			resReq, _ := getter.GetByProc("web")
			Expect(resReq.Requests.Cpu().Equal(resource.MustParse("200m"))).To(BeTrue())
			Expect(resReq.Requests.Memory().Equal(resource.MustParse("256Mi"))).To(BeTrue())
			Expect(resReq.Limits.Cpu().Equal(resource.MustParse("4"))).To(BeTrue())
			Expect(resReq.Limits.Memory().Equal(resource.MustParse("1Gi"))).To(BeTrue())
		})

		It("Get Default Requests", func() {
			originalConfig := config.Global
			projConf := paasv1alpha1.NewProjectConfig()
			projConf.ResRequests.ProcDefaultCPURequest = "100m"
			projConf.ResRequests.ProcDefaultMemRequest = "128Mi"
			config.SetConfig(projConf)
			defer config.SetConfig(originalConfig)

			bkapp.SetAnnotations(map[string]string{paasv1alpha2.EnvironmentKey: "stag"})
			bkapp.Spec.EnvOverlay = &paasv1alpha2.AppEnvOverlay{
				ResQuotas: []paasv1alpha2.ResQuotaOverlay{
					{EnvName: "stag", Process: "web", Plan: paasv1alpha2.ResQuotaPlan4C1G},
				},
			}
			getter := NewProcResourcesGetter(bkapp)
			resReq, _ := getter.GetByProc("web")
			Expect(resReq.Requests.Cpu().Equal(resource.MustParse("100m"))).To(BeTrue())
			Expect(resReq.Requests.Memory().Equal(resource.MustParse("128Mi"))).To(BeTrue())
			Expect(resReq.Limits.Cpu().Equal(resource.MustParse("4"))).To(BeTrue())
			Expect(resReq.Limits.Memory().Equal(resource.MustParse("1Gi"))).To(BeTrue())
		})

		It("Get Standard", func() {
			bkapp.Spec.Processes[1].ResQuotaPlan = paasv1alpha2.ResQuotaPlan4C2G
			getter := NewProcResourcesGetter(bkapp)

			resReq, _ := getter.GetByProc("web")
			Expect(resReq.Requests.Cpu().Equal(resource.MustParse("200m"))).To(BeTrue())
			Expect(resReq.Requests.Memory().Equal(resource.MustParse("256Mi"))).To(BeTrue())
			Expect(resReq.Limits.Cpu().Equal(resource.MustParse("4"))).To(BeTrue())
			Expect(resReq.Limits.Memory().Equal(resource.MustParse("1024Mi"))).To(BeTrue())

			resReq, _ = getter.GetByProc("worker")
			Expect(resReq.Requests.Cpu().Equal(resource.MustParse("200m"))).To(BeTrue())
			Expect(resReq.Requests.Memory().Equal(resource.MustParse("1Gi"))).To(BeTrue())
			Expect(resReq.Limits.Cpu().Equal(resource.MustParse("4"))).To(BeTrue())
			Expect(resReq.Limits.Memory().Equal(resource.MustParse("2Gi"))).To(BeTrue())
		})
	})

	Context("Test parseCustomResQuotaPlan", func() {
		It("should parse valid custom plan", func() {
			getter := NewProcResourcesGetter(bkapp)
			cpu, mem, ok := getter.parseCustomResQuotaPlan("4C2G")
			Expect(ok).To(BeTrue())
			Expect(cpu).To(Equal("4000m"))
			Expect(mem).To(Equal("1907Mi"))
		})

		It("should parse custom plan with decimal", func() {
			getter := NewProcResourcesGetter(bkapp)
			cpu, mem, ok := getter.parseCustomResQuotaPlan("0.5C1.5G")
			Expect(ok).To(BeTrue())
			Expect(cpu).To(Equal("500m"))
			Expect(mem).To(Equal("1430Mi"))
		})

		It("should parse custom plan with M unit", func() {
			getter := NewProcResourcesGetter(bkapp)
			cpu, mem, ok := getter.parseCustomResQuotaPlan("2C512M")
			Expect(ok).To(BeTrue())
			Expect(cpu).To(Equal("2000m"))
			// 512M = 512*1000*1000 bytes ≈ 488 MiB
			Expect(mem).To(Equal("488Mi"))
		})

		It("should parse custom plan with Gi unit", func() {
			getter := NewProcResourcesGetter(bkapp)
			cpu, mem, ok := getter.parseCustomResQuotaPlan("4C2Gi")
			Expect(ok).To(BeTrue())
			Expect(cpu).To(Equal("4000m"))
			Expect(mem).To(Equal("2048Mi"))
		})

		It("should parse custom plan with Mi unit", func() {
			getter := NewProcResourcesGetter(bkapp)
			cpu, mem, ok := getter.parseCustomResQuotaPlan("4C2048Mi")
			Expect(ok).To(BeTrue())
			Expect(cpu).To(Equal("4000m"))
			Expect(mem).To(Equal("2048Mi"))
		})

		It("should return false for invalid format", func() {
			getter := NewProcResourcesGetter(bkapp)
			_, _, ok := getter.parseCustomResQuotaPlan("invalid")
			Expect(ok).To(BeFalse())
		})

		It("should return false for zero CPU", func() {
			getter := NewProcResourcesGetter(bkapp)
			_, _, ok := getter.parseCustomResQuotaPlan("0C1G")
			Expect(ok).To(BeFalse())
		})

		It("should return false for zero memory", func() {
			getter := NewProcResourcesGetter(bkapp)
			_, _, ok := getter.parseCustomResQuotaPlan("1C0G")
			Expect(ok).To(BeFalse())
		})

		It("should return false for invalid unit", func() {
			getter := NewProcResourcesGetter(bkapp)
			_, _, ok := getter.parseCustomResQuotaPlan("1C1X")
			Expect(ok).To(BeFalse())
		})
	})
})
