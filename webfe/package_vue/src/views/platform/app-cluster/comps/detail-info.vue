<template>
  <div class="cluster-detail-info">
    <bk-button
      class="clustertab-edit-btn-cls"
      theme="primary"
      :outline="true"
      @click="handleEdit"
    >
      {{ $t('编辑') }}
    </bk-button>
    <div class="view-title">{{ $t('基本信息') }}</div>
    <DetailsRow
      v-for="(val, key) in baseInfoKeys"
      :key="key"
      :label-width="labelWidth"
      :align="key === 'api_servers' ? 'flex-start' : 'center'"
    >
      <template slot="label">{{ `${val}：` }}</template>
      <template slot="value">
        <div
          class="dot-wrapper"
          v-if="key === 'clusterToken'"
        >
          <span
            class="dot"
            v-for="i in 7"
            :key="i"
          ></span>
        </div>
        <template v-else-if="key === 'api_servers'">
          <template v-if="!displayInfoData[key]">--</template>
          <div
            v-else
            v-for="item in displayInfoData[key]"
            :key="item"
          >
            {{ item }}
          </div>
        </template>
        <template v-else>
          {{ key === 'cluster_source' ? clusterSourceMap[displayInfoData[key]] : displayInfoData[key] || '--' }}
        </template>
      </template>
    </DetailsRow>
    <div class="view-title">{{ $t('ElasticSearch 集群信息') }}</div>
    <DetailsRow
      v-for="(val, key) in configKeys"
      :key="key"
      :label-width="labelWidth"
    >
      <template slot="label">{{ `${val}：` }}</template>
      <template slot="value">
        <!-- 密码 -->
        <div
          class="dot-wrapper"
          v-if="key === 'password'"
        >
          <span
            v-for="i in 7"
            class="dot"
            :key="i"
          ></span>
        </div>
        <template v-else>{{ data.elastic_search_config?.[key] || '--' }}</template>
      </template>
    </DetailsRow>
    <div class="view-title">{{ $t('租户信息') }}</div>
    <DetailsRow
      v-for="(val, key) in tenantKeys"
      :key="key"
      :label-width="labelWidth"
      :align="'flex-start'"
      :label="`${val}：`"
    >
      <template slot="value">
        <span v-if="!data[key]?.length">--</span>
        <span
          v-else
          class="border-tag"
          v-for="id in data[key]"
          :key="id"
        >
          {{ id }}
        </span>
      </template>
    </DetailsRow>
  </div>
</template>

<script>
import DetailsRow from '@/components/details-row';
export default {
  name: 'DetailInfo',
  components: {
    DetailsRow,
  },
  props: {
    data: {
      type: Object,
      default: () => {},
    },
  },
  data() {
    return {
      baseInfoKeys: {
        name: this.$t('集群名称'),
        description: this.$t('集群描述'),
        cluster_source: this.$t('集群来源'),
        bcs_project_name: this.$t('项目'),
        bcs_cluster_name: `BCS ${this.$t('集群')}`,
        bk_biz_name: this.$t('业务'),
        api_servers: `${this.$t('集群')} Server`,
        clusterToken: `${this.$t('集群')} Token`,
        container_log_dir: this.$t('容器日志目录'),
        access_entry_ip: this.$t('集群访问入口 IP'),
      },
      configKeys: {
        scheme: this.$t('协议'),
        host: this.$t('主机'),
        port: this.$t('端口'),
        username: this.$t('用户名'),
        password: this.$t('密码'),
      },
      tenantKeys: {
        available_tenant_ids: this.$t('可用租户'),
      },
      clusterSourceMap: {
        bcs: this.$t('BCS 集群'),
        native_k8s: this.$t('K8S 集群（不推荐，无法使用访问控制台等功能）'),
      },
    };
  },
  computed: {
    localLanguage() {
      return this.$store.state.localLanguage;
    },
    labelWidth() {
      return this.localLanguage === 'en' ? 150 : 100;
    },
    displayInfoData() {
      return {
        ...this.data,
        bcs_project_name: this.data.bcs_project_name || this.data.bcs_project_id,
        bcs_cluster_name: this.data.bcs_cluster_name || this.data.bcs_cluster_id,
        bk_biz_name: this.data.bk_biz_name || this.data.bk_biz_id,
      };
    },
  },
  methods: {
    handleEdit() {
      this.$router.push({
        name: 'clusterCreateEdit',
        params: {
          type: 'edit',
        },
        query: {
          id: this.data.name,
          step: 1,
          alone: true,
        },
      });
    },
  },
};
</script>

<style lang="scss" scoped>
.cluster-detail-info {
  position: relative;
  .dot-wrapper {
    display: flex;
    align-items: center;
    gap: 5px;
  }
  .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: #4d4f56;
  }
  .border-tag {
    margin-right: 4px;
  }
}
.view-title {
  font-weight: 700;
  font-size: 14px;
  color: #313238;
  line-height: 22px;
  margin-top: 24px;
  &:first-of-type {
    margin-top: 0;
  }
}
</style>
