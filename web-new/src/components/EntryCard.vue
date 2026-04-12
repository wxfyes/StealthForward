<script setup>
// This replacement is just a placeholder as I need to find another file.
import { inject, computed, ref } from 'vue'
import { useApi } from '../composables/useApi'

const props = defineProps({
  entry: Object
})

const emit = defineEmits(['edit', 'refresh'])

const exits = inject('exits')
const trafficStats = inject('trafficStats')
const settings = inject('settings')
const { apiDelete, apiPost, apiGet } = useApi()

const rotating = ref(false)

const targetExitName = computed(() => {
  const ex = exits.value.find(e => e.id === props.entry.target_exit_id)
  return ex ? ex.name : '不绑定'
})

// Calculate total traffic for this entry
const entryTraffic = computed(() => {
  if (!trafficStats.value || !trafficStats.value.entry_stats) return 0
  const stats = trafficStats.value.entry_stats[props.entry.id]
  if (!stats) return 0
  return (stats.upload || 0) + (stats.download || 0)
})

const nodeStats = computed(() => {
  if (!trafficStats.value || !trafficStats.value.node_stats) return null
  return trafficStats.value.node_stats[props.entry.id] || null
})

async function handleDelete() {
  if (!confirm('确定删除此入口节点?')) return
  try {
    await apiDelete(`/api/v1/entries/${props.entry.id}`)
    emit('refresh')
  } catch (e) {
    alert('删除失败: ' + e.message)
  }
}

async function rotateIP() {
  if (!props.entry.cloud_provider || props.entry.cloud_provider === 'none') {
    if (confirm('此入口尚未绑定云实例，是否尝试根据当前 IP 自动识别并绑定？')) {
      rotating.value = true
      try {
        const res = await apiGet(`/api/v1/cloud/auto-detect?ip=${props.entry.ip}`)
        await apiPost('/api/v1/entries', {
          ...props.entry,
          cloud_provider: res.provider,
          cloud_region: res.region,
          cloud_instance_id: res.instance_id,
          cloud_record_name: res.record_name || (props.entry.domain.split('.')[0])
        })
        alert(`识别成功: ${res.provider} (${res.region})。已自动绑定并保存。`)
        emit('refresh')
      } catch (e) {
        alert('自动识别失败: ' + e.message)
        rotating.value = false
        return
      }
    } else {
      return
    }
  }

  if (!confirm('确定要更换此入口节点的 IP?')) return
  rotating.value = true
  try {
    const res = await apiPost(`/api/v1/node/${props.entry.id}/rotate-ip`, {
      region: props.entry.cloud_region,
      instance_id: props.entry.cloud_instance_id,
      zone_name: settings?.value?.['cloudflare.default_zone'] || '',
      record_name: props.entry.cloud_record_name
    })
    alert('IP 更换成功！新 IP: ' + res.new_ip)
    emit('refresh')
  } catch (e) {
    alert('IP 更换失败: ' + e.message)
  } finally {
    rotating.value = false
  }
}

async function toggleAutoRotate() {
  try {
    const newVal = !props.entry.auto_rotate_ip
    await apiPost(`/api/v1/entries/${props.entry.id}`, {
      ...props.entry,
      auto_rotate_ip: newVal
    })
    emit('refresh')
  } catch (e) {
    alert('操作失败: ' + e.message)
  }
}

const issuingCert = ref(false)
async function issueCertificate() {
  if (!props.entry.domain) {
    alert('请先编辑节点并填写域名')
    return
  }
  if (!confirm(`确定为域名 ${props.entry.domain} 申请证书? 请确保域名已解析到当前 IP: ${props.entry.ip}`)) return
  issuingCert.value = true
  try {
    const res = await apiPost('/api/v1/entries/issue-cert', { domain: props.entry.domain })
    alert(res.message)
  } catch (e) {
    alert('申请指令发送失败: ' + e.message)
  } finally {
    issuingCert.value = false
  }
}

const provisioning = ref(false)

async function reprovisionNode() {
  if (!confirm('确定触发自动化初始化? 这将尝试 SSH 连入中转机并开启 BBR、优化内核、安装 Agent。请确保已在设置中配置 SSH 密钥。')) return
  provisioning.value = true
  try {
    const res = await apiPost(`/api/v1/entries/${props.entry.id}/reprovision`)
    alert(res.message)
  } catch (e) {
    alert('启动失败: ' + e.message)
  } finally {
    provisioning.value = false
  }
}

function copyUpdateCommand() {
  const version = import.meta.env.VITE_APP_VERSION || 'Dev'
  const cmd = `curl -fsSL https://raw.githubusercontent.com/wangn9900/StealthForward/main/scripts/install.sh | bash -s -- --update-agent ${version}`
  
  navigator.clipboard.writeText(cmd).then(() => {
    alert('Agent 更新命令已复制！(版本: ' + version + ')')
  })
}

function copyInstallCommand() {
  const token = settings.value['system.communication_token'] || 'YOUR_TOKEN'
  const host = window.location.origin
  const cmd = `export CTRL_ADDR='${host}' && export NODE_ID='${props.entry.id}' && export CTRL_TOKEN='${token}' && export CTRL_DOMAIN='${props.entry.domain}' && curl -fsSL https://raw.githubusercontent.com/wangn9900/StealthForward/main/scripts/install.sh | bash -s -- 2`
  
  navigator.clipboard.writeText(cmd).then(() => {
    alert('一键安装/对接命令已复制！\n说明：请在目标中转机(root)执行此命令即可完成对接。')
  })
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

function formatSpeed(bytesPerSec) {
  if (!bytesPerSec) return '0 B/s'
  const k = 1024
  const sizes = ['B/s', 'K/s', 'M/s', 'G/s']
  const i = Math.floor(Math.log(bytesPerSec) / Math.log(k))
  return parseFloat((bytesPerSec / Math.pow(k, i)).toFixed(1)) + sizes[i]
}

function formatUptime(seconds) {
  if (!seconds) return 'OFF'
  const h = Math.floor(seconds / 3600)
  if (h > 24) return `${Math.floor(h/24)}d ${h%24}h`
  return `${h}h`
}

const clearingTraffic = ref(false)
async function clearTraffic() {
  if (!confirm('确定清除此入口节点的流量统计？此操作不可逆！')) return
  clearingTraffic.value = true
  try {
    await apiDelete(`/api/v1/traffic/entry/${props.entry.id}`)
    emit('refresh')
  } catch (e) {
    alert('清除失败: ' + e.message)
  } finally {
    clearingTraffic.value = false
  }
}
</script>

<template>
  <div class="compact-card group">
    <!-- TopRow: Basic Info & Main Controls -->
    <div class="top-row">
      <div class="node-brief">
        <div class="icon-circle">
          <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
        </div>
        <div class="name-box">
          <div class="flex items-center gap-1.5">
            <span class="name">{{ entry.name }}</span>
            <span class="id">#{{ entry.id }}</span>
          </div>
          <span class="addr">{{ entry.ip }} / {{ entry.domain }}</span>
        </div>
      </div>

      <div class="pill-group">
        <div class="pill">
          <span class="p-label">落地</span>
          <span class="p-val">{{ targetExitName }}</span>
        </div>
        <div class="pill" :class="{ 'active': entry.v2board_url }">
          <span class="p-label">API</span>
          <span class="p-val">{{ entry.v2board_url ? 'ON' : 'OFF' }}</span>
        </div>
      </div>

      <div class="main-btns">
        <div class="mini-switch" @click="toggleAutoRotate" :class="{ 'on': entry.auto_rotate_ip }" title="自动换IP">
          <div class="t"></div>
        </div>
        <button @click="rotateIP" :disabled="rotating" class="btn-rotate" title="换IP">
           <svg class="w-3.5 h-3.5" :class="{'animate-spin': rotating}" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" /></svg>
        </button>
        <button @click="issueCertificate" :disabled="issuingCert" class="btn-tool" style="color: #ec4899" title="申请/重签 SSL 证书">
          <svg class="w-3.5 h-3.5" :class="{'animate-pulse text-pink-400': issuingCert}" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
        </button>
        <button @click="reprovisionNode" :disabled="provisioning" class="btn-tool" style="color: #6366f1" title="自动化部署 (BBR+对接)">
          <svg class="w-3.5 h-3.5" :class="{'animate-bounce': provisioning}" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
        </button>
        <button @click="copyInstallCommand" class="btn-tool" style="color: #10b981" title="复制一键安装/对接命令">
          <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" /></svg>
        </button>
        <button @click="copyUpdateCommand" class="btn-tool" title="更新脚本"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg></button>
        <button @click="$emit('edit', entry)" class="btn-tool" title="编辑节点"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" /></svg></button>
        <button @click="handleDelete" class="btn-tool del" title="删除节点"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg></button>
      </div>
    </div>

    <!-- BottomRow: Realtime Horizontal Stats -->
    <div class="stats-row" v-if="nodeStats">
      <div class="stat-item cpu">
        <span class="sl">CPU</span>
        <div class="bar-wrap"><div class="bar" :style="{ width: nodeStats.cpu + '%' }"></div></div>
        <span class="sv">{{ nodeStats.cpu.toFixed(0) }}%</span>
      </div>
      <div class="stat-item mem">
        <span class="sl">MEM</span>
        <div class="bar-wrap"><div class="bar" :style="{ width: nodeStats.mem + '%' }"></div></div>
        <span class="sv">{{ nodeStats.mem.toFixed(0) }}%</span>
      </div>
      <div class="divider"></div>
      <div class="data-group">
        <div class="di">
          <span class="dl">NET ↓↑</span>
          <span class="dv">{{ formatSpeed(nodeStats.net_in) }} / {{ formatSpeed(nodeStats.net_out) }}</span>
        </div>
        <div class="di">
          <span class="dl">LOAD</span>
          <span class="dv">{{ nodeStats.load1.toFixed(1) }}</span>
        </div>
        <div class="di">
          <span class="dl">UPTIME</span>
          <span class="dv">{{ formatUptime(nodeStats.uptime) }}</span>
        </div>
        <div class="di">
          <span class="dl">TOTAL</span>
          <div class="dv-wrap">
            <span class="dv">{{ formatBytes(entryTraffic) }}</span>
            <button 
              @click="clearTraffic" 
              :disabled="clearingTraffic" 
              class="clear-btn" 
              title="清除流量统计"
            >
              <svg class="w-2.5 h-2.5" :class="{'animate-spin': clearingTraffic}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="waiting-row">
      <div class="pulse"></div>
      <span>等待探针接入节点 #{{ entry.id }}...</span>
    </div>
  </div>
</template>

<style scoped>
.compact-card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: 1.25rem;
  padding: 1rem 1.25rem;
  margin-bottom: 0.75rem;
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  box-shadow: 0 2px 8px rgba(0,0,0,0.02);
}

.compact-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 12px 30px -10px rgba(0,0,0,0.08);
  border-color: var(--accent);
}

.top-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
}

.node-brief {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex: 0 0 280px;
}

.icon-circle {
  width: 2.75rem;
  height: 2.75rem;
  background: var(--bg-secondary);
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--accent);
}

.name-box .name {
  font-size: 1.05rem;
  font-weight: 800;
  color: var(--text-primary);
  letter-spacing: -0.01em;
}

.name-box .id {
  font-size: 0.65rem;
  font-family: inherit;
  background: var(--bg-secondary);
  color: var(--text-muted);
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 700;
}

.name-box .addr {
  display: block;
  font-size: 0.75rem;
  color: var(--text-muted);
  font-family: 'JetBrains Mono', monospace;
  margin-top: 1px;
}

.pill-group {
  display: flex;
  gap: 0.5rem;
}

.pill {
  background: var(--bg-secondary);
  padding: 0.4rem 0.75rem;
  border-radius: 0.75rem;
  display: flex;
  flex-direction: column;
  min-width: 70px;
}

.pill .p-label { font-size: 0.5rem; text-transform: uppercase; font-weight: 800; color: var(--text-muted); }
.pill .p-val { font-size: 0.8rem; font-weight: 700; color: var(--text-primary); }
.pill.active .p-val { color: #10b981; }

.main-btns {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.mini-switch {
  width: 32px;
  height: 18px;
  background: var(--border-color);
  border-radius: 20px;
  position: relative;
  cursor: pointer;
  transition: all 0.3s;
}

.mini-switch.on { background: var(--accent); }
.mini-switch .t {
  width: 12px;
  height: 12px;
  background: #fff;
  border-radius: 50%;
  position: absolute;
  top: 3px;
  left: 3px;
  transition: all 0.3s;
}
.mini-switch.on .t { transform: translateX(14px); }

.btn-rotate {
  background: var(--accent);
  color: #fff;
  padding: 0.5rem 0.85rem;
  border-radius: 0.75rem;
  font-size: 0.75rem;
  font-weight: 800;
  transition: all 0.3s;
  box-shadow: 0 4px 10px rgba(var(--accent-rgb), 0.2);
}

.btn-tool {
  width: 2.25rem;
  height: 2.25rem;
  background: var(--bg-secondary);
  border-radius: 0.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--text-secondary);
  transition: all 0.2s;
}

.btn-tool:hover { background: var(--accent); color: #fff; }
.btn-tool.del:hover { background: #fee2e2; color: #ef4444; }

/* Stats Row - Compact & Horizontal */
.stats-row {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px dashed var(--border-color);
  display: flex;
  align-items: center;
  gap: 1.5rem;
}

.stat-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex: 0 0 120px;
}

.stat-item .sl { font-size: 0.65rem; font-weight: 900; color: var(--text-muted); width: 2.5rem; }
.stat-item .sv { font-size: 0.75rem; font-weight: 800; color: var(--text-primary); font-family: 'JetBrains Mono', monospace; width: 2.5rem; text-align: right; }

.bar-wrap { flex: 1; height: 4px; background: var(--bg-secondary); border-radius: 2px; overflow: hidden; }
.bar { height: 100%; background: var(--accent); border-radius: 2px; transition: width 1s; }

.divider { width: 1px; height: 1.5rem; background: var(--border-color); }

.data-group {
  flex: 1;
  display: flex;
  justify-content: space-between;
}

.di { display: flex; flex-direction: column; }
.di .dl { font-size: 0.55rem; text-transform: uppercase; font-weight: 800; color: var(--text-muted); letter-spacing: 0.05em; }
.di .dv { font-size: 0.75rem; font-weight: 800; color: var(--text-primary); font-family: 'JetBrains Mono', monospace; margin-top: 1px; }

.dv-wrap { display: flex; align-items: center; gap: 0.25rem; }
.clear-btn {
  background: transparent;
  border: none;
  padding: 2px;
  color: var(--text-muted);
  cursor: pointer;
  opacity: 0;
  transition: all 0.2s;
}
.compact-card:hover .clear-btn { opacity: 0.5; }
.clear-btn:hover { opacity: 1; color: #ef4444; }

.waiting-row {
  margin-top: 1rem;
  padding: 0.5rem;
  background: var(--bg-secondary);
  border-radius: 0.75rem;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  font-size: 0.7rem;
  font-weight: 700;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

.pulse { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; animation: pulse 1.5s infinite; }
@keyframes pulse { 0% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.5); opacity: 0.5; } 100% { transform: scale(1); opacity: 1; } }

@media (max-width: 1024px) {
  .top-row { flex-direction: column; align-items: flex-start; gap: 1rem; }
  .stats-row { flex-direction: column; align-items: stretch; }
  .data-group { grid-template-cols: 1fr 1fr; display: grid; gap: 0.75rem; }
}
</style>
