<script setup>
import { ref, inject, computed } from 'vue'

const emit = defineEmits(['refresh'])

// Inject Shared States
const portForwards = inject('portForwards', ref([]))
const entries = inject('entries', ref([]))
const apiGet = inject('apiGet')
const apiPost = inject('apiPost')

// Search & Filter
const searchQuery = ref('')
const selectedEntryFilter = ref('')

const filteredRules = computed(() => {
  return portForwards.value.filter(r => {
    const matchesSearch = r.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                          r.target_addr.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                          String(r.listen_port).includes(searchQuery.value)
    const matchesEntry = !selectedEntryFilter.value || r.entry_node_id === Number(selectedEntryFilter.value)
    return matchesSearch && matchesEntry
  })
})

// Stats
const totalRules = computed(() => portForwards.value.length)
const activeRulesCount = computed(() => portForwards.value.filter(r => r.status === 'running').length)
const totalTraffic = computed(() => {
  let bytes = 0
  portForwards.value.forEach(r => {
    bytes += (r.upload || 0) + (r.download || 0)
  })
  return formatBytes(bytes)
})

// Modal states
const showAddModal = ref(false)
const showEditModal = ref(false)
const submitting = ref(false)

// Form states
const form = ref({
  id: null,
  name: '',
  entry_node_id: '',
  listen_port: 10080,
  type: 'realm',
  tunnel_type: 'none',
  target_addr: '',
  status: 'running'
})

function resetForm() {
  form.value = {
    id: null,
    name: '',
    entry_node_id: entries.value[0]?.id || '',
    listen_port: 10080,
    type: 'realm',
    tunnel_type: 'none',
    target_addr: '',
    status: 'running'
  }
}

function openAddModal() {
  resetForm()
  showAddModal.value = true
}

function openEditModal(rule) {
  form.value = { ...rule }
  showEditModal.value = true
}

// Actions
async function handleSubmit(isEdit = false) {
  if (!form.value.name || !form.value.entry_node_id || !form.value.listen_port || !form.value.target_addr) {
    alert('请填写完整规则信息')
    return
  }

  submitting.value = true
  try {
    const payload = {
      ...form.value,
      entry_node_id: Number(form.value.entry_node_id),
      listen_port: Number(form.value.listen_port)
    }

    let url = '/api/v1/portforwards'
    if (isEdit) {
      url = `/api/v1/portforwards/${form.value.id}`
    }

    let res
    if (isEdit) {
      const token = localStorage.getItem('stealth_token')
      const response = await fetch(url, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': token
        },
        body: JSON.stringify(payload)
      })
      if (response.ok) {
        res = await response.json()
      } else {
        const errData = await response.json().catch(() => ({}))
        res = { error: errData.error || `HTTP 错误: ${response.status}` }
      }
    } else {
      res = await apiPost(url, payload)
    }

    if (res && !res.error) {
      showAddModal.value = false
      showEditModal.value = false
      emit('refresh')
    } else {
      alert(res?.error || '操作失败')
    }
  } catch (err) {
    alert(err.message || '网络错误')
  } finally {
    submitting.value = false
  }
}

async function handleToggle(rule) {
  try {
    const res = await apiPost(`/api/v1/portforwards/toggle/${rule.id}`)
    if (res && !res.error) {
      emit('refresh')
    } else {
      alert(res?.error || '操作失败')
    }
  } catch (err) {
    alert(err.message || '网络错误')
  }
}

async function handleClear(rule) {
  if (!confirm(`确定要清空规则 [${rule.name}] 的流量统计吗？`)) return
  try {
    const res = await apiPost(`/api/v1/portforwards/clear/${rule.id}`)
    if (res && !res.error) {
      emit('refresh')
    } else {
      alert(res?.error || '操作失败')
    }
  } catch (err) {
    alert(err.message || '网络错误')
  }
}

async function handleDelete(rule) {
  if (!confirm(`确定要删除端口转发规则 [${rule.name}] 吗？`)) return
  try {
    // 调用 Delete 路由
    const token = localStorage.getItem('stealth_token')
    const res = await fetch(`/api/v1/portforwards/${rule.id}`, {
      method: 'DELETE',
      headers: {
        'Authorization': token
      }
    })
    if (res.ok) {
      emit('refresh')
    } else {
      const data = await res.json()
      alert(data.error || '删除失败')
    }
  } catch (err) {
    alert('网络错误')
  }
}

// Helpers
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0.00 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

function getEntryNodeName(id) {
  const entry = entries.value.find(e => e.id === id)
  return entry ? entry.name : `未知节点 (ID: ${id})`
}

// Diagnose Modal States & Methods
const showDiagnoseModal = ref(false)
const diagnosing = ref(false)
const diagnoseResult = ref(null)

async function runDiagnose(rule) {
  showDiagnoseModal.value = true
  diagnosing.value = true
  diagnoseResult.value = null
  try {
    const res = await apiGet(`/api/v1/portforwards/diagnose/${rule.id}`)
    if (res && !res.error) {
      diagnoseResult.value = res
    } else {
      alert(res?.error || '诊断失败')
      showDiagnoseModal.value = false
    }
  } catch (err) {
    alert(err.message || '网络连接失败')
    showDiagnoseModal.value = false
  } finally {
    diagnosing.value = false
  }
}

function getEntryConnectAddr(rule) {
  if (!entries || !entries.value) return `:${rule?.listen_port}`
  const entry = entries.value.find(e => e.id === rule.entry_node_id)
  if (!entry) return `:${rule.listen_port}`
  const host = entry.domain || entry.ip
  return `${host}:${rule.listen_port}`
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => {
    alert('中转地址已成功复制到剪贴板！')
  }).catch(() => {
    const input = document.createElement('input')
    input.setAttribute('value', text)
    document.body.appendChild(input)
    input.select()
    document.execCommand('copy')
    document.body.removeChild(input)
    alert('中转地址已成功复制！')
  })
}
</script>

<template>
  <div class="space-y-6">
    
    <!-- Stats Banner -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div class="glass p-5 rounded-3xl flex items-center justify-between">
        <div>
          <div class="text-sm font-medium text-[var(--text-muted)] mb-1">总转发规则</div>
          <div class="text-3xl font-light">{{ totalRules }} <span class="text-xs text-[var(--text-muted)]">Rules</span></div>
        </div>
        <div class="p-3 bg-primary-500/10 rounded-2xl">
          <svg class="w-6 h-6 text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />
          </svg>
        </div>
      </div>
      
      <div class="glass p-5 rounded-3xl flex items-center justify-between">
        <div>
          <div class="text-sm font-medium text-[var(--text-muted)] mb-1">运行中规则</div>
          <div class="text-3xl font-light text-emerald-400">{{ activeRulesCount }} <span class="text-xs text-[var(--text-muted)]">Active</span></div>
        </div>
        <div class="p-3 bg-emerald-500/10 rounded-2xl">
          <svg class="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
      </div>

      <div class="glass p-5 rounded-3xl flex items-center justify-between">
        <div>
          <div class="text-sm font-medium text-[var(--text-muted)] mb-1">总跑量 (免审计)</div>
          <div class="text-3xl font-light text-amber-400">{{ totalTraffic }}</div>
        </div>
        <div class="p-3 bg-amber-500/10 rounded-2xl">
          <svg class="w-6 h-6 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
          </svg>
        </div>
      </div>
    </div>

    <!-- Actions & Filter bar -->
    <div class="glass p-4 rounded-3xl flex flex-col md:flex-row justify-between items-center gap-4">
      <div class="flex flex-wrap items-center gap-3 w-full md:w-auto">
        <button @click="openAddModal" class="bg-primary-600 hover:bg-primary-500 text-white font-bold text-sm px-4 py-2.5 rounded-2xl transition flex items-center gap-2">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          新建规则
        </button>
      </div>

      <div class="flex flex-col md:flex-row gap-3 w-full md:w-auto items-center">
        <!-- Entry filter -->
        <select v-model="selectedEntryFilter" class="glass px-4 py-2 rounded-2xl text-sm focus:ring-0 outline-none w-full md:w-48 text-gray-800 dark:text-white bg-white/20 dark:bg-black/20 border border-black/5 dark:border-white/5">
          <option value="" class="text-gray-800 dark:text-white bg-white dark:bg-zinc-800">所有入口节点</option>
          <option v-for="e in entries" :key="e.id" :value="e.id" class="text-gray-800 dark:text-white bg-white dark:bg-zinc-800">{{ e.name }}</option>
        </select>
        <!-- Search -->
        <div class="relative w-full md:w-64">
          <input v-model="searchQuery" type="text" placeholder="搜索规则名称、端口、落地..." class="glass pl-10 pr-4 py-2 rounded-2xl text-sm focus:ring-0 outline-none text-gray-800 dark:text-white placeholder-gray-400 w-full bg-white/20 dark:bg-black/20 border border-black/5 dark:border-white/5" />
          <svg class="w-4 h-4 absolute left-3.5 top-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
        </div>
      </div>
    </div>

    <!-- Rules List -->
    <div class="glass rounded-3xl overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full text-left border-collapse">
          <thead>
            <tr class="border-b border-white/5 text-[var(--text-muted)] text-sm font-medium">
              <th class="p-4 pl-6">规则名称</th>
              <th class="p-4">入口节点</th>
              <th class="p-4">中转入口地址</th>
              <th class="p-4">转发模式</th>
              <th class="p-4">目标落地</th>
              <th class="p-4 text-right">上行/下行</th>
              <th class="p-4 text-center">状态</th>
              <th class="p-4 pr-6 text-center">操作</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-white/5">
            <tr v-if="filteredRules.length === 0">
              <td colspan="8" class="p-8 text-center text-[var(--text-muted)] font-light text-sm">暂无匹配的端口转发规则</td>
            </tr>
            <tr v-for="rule in filteredRules" :key="rule.id" class="hover:bg-white/5 transition text-sm">
              <td class="p-4 pl-6 font-medium text-gray-800 dark:text-white">{{ rule.name }}</td>
              <td class="p-4 text-gray-600 dark:text-gray-300">{{ getEntryNodeName(rule.entry_node_id) }}</td>
              <td class="p-4 font-mono font-bold text-primary-400">
                <div class="flex items-center gap-1.5">
                  <span class="truncate max-w-[400px] lg:max-w-none" :title="getEntryConnectAddr(rule)">{{ getEntryConnectAddr(rule) }}</span>
                  <button @click="copyText(getEntryConnectAddr(rule))" class="p-1 rounded hover:bg-black/10 dark:hover:bg-white/10 text-gray-400 hover:text-gray-600 dark:hover:text-white transition" title="复制中转连接地址">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
                    </svg>
                  </button>
                </div>
              </td>
              <td class="p-4 uppercase text-xs font-bold">
                <span :class="rule.type === 'realm' ? 'text-indigo-400' : 'text-sky-400'">
                  {{ rule.type }}
                </span>
              </td>
              <td class="p-4 font-mono text-xs text-gray-500 dark:text-gray-400 max-w-[350px] lg:max-w-none truncate" :title="rule.target_addr">{{ rule.target_addr }}</td>
              <td class="p-4 text-right font-mono text-xs">
                <div class="text-emerald-400">↑ {{ formatBytes(rule.upload) }}</div>
                <div class="text-indigo-400">↓ {{ formatBytes(rule.download) }}</div>
              </td>
              <td class="p-4 text-center">
                <span :class="['inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium', 
                  rule.status === 'running' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-gray-500/10 text-gray-400']">
                  <span :class="['w-1.5 h-1.5 rounded-full', rule.status === 'running' ? 'bg-emerald-500 animate-pulse' : 'bg-gray-500']"></span>
                  {{ rule.status === 'running' ? '运行中' : '已暂停' }}
                </span>
              </td>
              <td class="p-4 pr-6">
                <div class="flex justify-center gap-2">
                  <button @click="handleToggle(rule)" :class="['p-1.5 rounded-xl transition', rule.status === 'running' ? 'hover:bg-amber-500/10 text-amber-400' : 'hover:bg-emerald-500/10 text-emerald-400']" :title="rule.status === 'running' ? '暂停' : '启动'">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path v-if="rule.status === 'running'" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                      <path v-else stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                    </svg>
                  </button>
                  <button @click="runDiagnose(rule)" class="p-1.5 rounded-xl hover:bg-sky-500/10 text-sky-400 transition" title="诊断联通性">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </button>
                  <button @click="handleClear(rule)" class="p-1.5 rounded-xl hover:bg-amber-500/10 text-amber-400 transition" title="清空流量">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                  <button @click="openEditModal(rule)" class="p-1.5 rounded-xl hover:bg-black/10 dark:hover:bg-white/10 text-gray-600 dark:text-white transition" title="编辑">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
                    </svg>
                  </button>
                  <button @click="handleDelete(rule)" class="p-1.5 rounded-xl hover:bg-rose-500/10 text-rose-400 transition" title="删除">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Add/Edit Modals (Glassmorphism Modal) -->
    <div v-if="showAddModal || showEditModal" class="fixed inset-0 bg-black/60 backdrop-blur-md flex items-center justify-center p-4 z-50 animate-fade-in">
      <div class="glass rounded-3xl w-full max-w-lg overflow-hidden border border-white/10 shadow-2xl">
        <div class="p-6 border-b border-white/5 flex justify-between items-center">
          <h3 class="text-lg font-bold text-white">{{ showEditModal ? '编辑中转规则' : '创建端口转发规则' }}</h3>
          <button @click="showAddModal = false; showEditModal = false" class="text-gray-400 hover:text-white transition">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        <div class="p-6 space-y-4">
          <!-- Name -->
          <div>
            <label class="block text-xs font-semibold text-gray-400 dark:text-gray-300 uppercase mb-2">规则名称</label>
            <input v-model="form.name" type="text" placeholder="例如: HK-Reality" class="glass px-4 py-2.5 rounded-2xl w-full text-sm text-gray-800 dark:text-white bg-white/20 dark:bg-black/20 focus:ring-0 outline-none border border-black/5 dark:border-white/5" />
          </div>

          <!-- Entry Node -->
          <div>
            <label class="block text-xs font-semibold text-gray-400 dark:text-gray-300 uppercase mb-2">入口中转服务器</label>
            <select v-model="form.entry_node_id" class="glass px-4 py-2.5 rounded-2xl w-full text-sm text-gray-800 dark:text-white bg-white/20 dark:bg-black/20 focus:ring-0 outline-none border border-black/5 dark:border-white/5">
              <option v-for="e in entries" :key="e.id" :value="e.id" class="text-gray-800 dark:text-white bg-white dark:bg-zinc-800">{{ e.name }}</option>
            </select>
          </div>

          <div class="grid grid-cols-2 gap-4">
            <!-- Port -->
            <div>
              <label class="block text-xs font-semibold text-gray-400 dark:text-gray-300 uppercase mb-2">中转监听端口 (1-65535)</label>
              <input v-model="form.listen_port" type="number" min="1" max="65535" class="glass px-4 py-2.5 rounded-2xl w-full text-sm text-gray-800 dark:text-white bg-white/20 dark:bg-black/20 focus:ring-0 outline-none border border-black/5 dark:border-white/5 font-mono" />
            </div>

            <!-- Forward Engine -->
            <div>
              <label class="block text-xs font-semibold text-gray-400 dark:text-gray-300 uppercase mb-2">转发引擎</label>
              <select v-model="form.type" class="glass px-4 py-2.5 rounded-2xl w-full text-sm text-gray-800 dark:text-white bg-white/20 dark:bg-black/20 focus:ring-0 outline-none border border-black/5 dark:border-white/5">
                <option value="realm" class="text-gray-800 dark:text-white bg-white dark:bg-zinc-800">Realm (极轻量 / 零拷贝)</option>
                <option value="gost" class="text-gray-800 dark:text-white bg-white dark:bg-zinc-800">Gost (双向 TCP+UDP)</option>
              </select>
            </div>
          </div>

          <!-- Target Remote Address -->
          <div>
            <label class="block text-xs font-semibold text-gray-400 dark:text-gray-300 uppercase mb-2">落地目标地址 (IP:Port / 域名:Port)</label>
            <input v-model="form.target_addr" type="text" placeholder="例如: 203.88.117.67:443" class="glass px-4 py-2.5 rounded-2xl w-full text-sm text-gray-800 dark:text-white bg-white/20 dark:bg-black/20 focus:ring-0 outline-none border border-black/5 dark:border-white/5 font-mono" />
            <p class="text-[0.7rem] text-primary-500 dark:text-primary-400 mt-1.5 font-medium">★ 注意：转发为四层透明转发，请保证目的端口的真实性</p>
          </div>
        </div>

        <div class="p-6 border-t border-white/5 flex justify-end gap-3 bg-white/5">
          <button @click="showAddModal = false; showEditModal = false" class="glass px-4 py-2 rounded-2xl text-sm font-semibold text-gray-300 hover:text-white transition">取消</button>
          <button @click="handleSubmit(showEditModal)" :disabled="submitting" class="bg-primary-600 hover:bg-primary-500 text-white font-bold text-sm px-5 py-2 rounded-2xl transition disabled:opacity-50">
            {{ submitting ? '保存中...' : '确认保存' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Diagnose Modal (1:1 Match to Image 2) -->
    <div v-if="showDiagnoseModal" class="fixed inset-0 bg-black/60 backdrop-blur-md flex items-center justify-center p-4 z-50 animate-fade-in">
      <div class="glass rounded-3xl w-full max-w-lg overflow-hidden border border-white/10 shadow-2xl">
        <div class="p-6 border-b border-white/5 flex justify-between items-center">
          <h3 class="text-lg font-bold text-gray-800 dark:text-white">诊断结果 ({{ diagnoseResult ? `#${diagnoseResult.rule_id}` : '加载中...' }})</h3>
          <button @click="showDiagnoseModal = false" class="text-gray-400 hover:text-gray-600 dark:hover:text-white transition">
            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div class="p-6 space-y-5">
          <!-- Inbound Diagnose -->
          <div>
            <div class="text-sm font-bold text-gray-800 dark:text-white mb-2">入口诊断 (Inbound)</div>
            <div class="border border-black/5 dark:border-white/5 rounded-2xl p-4 bg-black/5 dark:bg-black/25">
              <div class="flex justify-between items-center mb-2">
                <span class="text-sm font-semibold text-gray-700 dark:text-gray-300">{{ diagnoseResult?.entry_name || '中转入口节点' }}</span>
                <span class="text-[0.7rem] px-2 py-0.5 rounded-md bg-primary-500/10 text-primary-500 border border-primary-500/20 font-mono">GID: {{ diagnoseResult?.rule_id || '-' }}</span>
              </div>
              
              <div class="text-xs text-gray-500 dark:text-gray-400 bg-white/50 dark:bg-zinc-800/50 p-3 rounded-xl border border-black/5 dark:border-white/5 font-mono space-y-1">
                <div class="text-xs font-bold text-gray-600 dark:text-gray-400 mb-1">诊断结果详情</div>
                <div v-if="diagnosing" class="animate-pulse text-primary-500">正在诊断联通性，请稍候...</div>
                <div v-else-if="diagnoseResult">
                  <div>目标地址数: 1/1</div>
                  <div :class="diagnoseResult.inbound_ok ? 'text-emerald-500 dark:text-emerald-400' : 'text-rose-500 dark:text-rose-400'">
                    [0] {{ diagnoseResult.inbound_ok ? `用时 ${diagnoseResult.inbound_ms} ms` : '连接超时' }} 地址: {{ diagnoseResult.inbound_addr }}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Outbounds Diagnose -->
          <div>
            <div class="text-sm font-bold text-gray-800 dark:text-white mb-2">出口诊断 (Outbounds)</div>
            <div class="text-xs text-gray-500 dark:text-gray-400 bg-white/50 dark:bg-zinc-800/50 p-4 rounded-xl border border-black/5 dark:border-white/5 font-mono">
              <div v-if="diagnosing" class="animate-pulse">正在检测落地端联通性...</div>
              <div v-else-if="diagnoseResult">
                <div v-if="diagnoseResult.outbound_ok" class="text-emerald-500 dark:text-emerald-400">
                  [0] 用时 {{ diagnoseResult.outbound_ms }} ms 地址: {{ diagnoseResult.outbound_addr }} (通畅)
                </div>
                <div v-else class="text-rose-500 dark:text-rose-400">
                  [0] 连接超时，地址: {{ diagnoseResult.outbound_addr }} (不可达)
                </div>
              </div>
            </div>
          </div>

          <!-- Backend Diagnose -->
          <div>
            <div class="text-sm font-bold text-gray-800 dark:text-white mb-2">面板反馈 (Backend)</div>
            <div class="text-xs text-gray-500 dark:text-gray-400 bg-white/50 dark:bg-zinc-800/50 p-4 rounded-xl border border-black/5 dark:border-white/5 font-mono space-y-1">
              <div>发出任务 1</div>
              <div>发出失败 {{ diagnoseResult && !diagnoseResult.inbound_ok ? 1 : 0 }}</div>
              <div>回收任务 1</div>
            </div>
          </div>
        </div>

        <div class="p-6 border-t border-white/5 flex justify-end bg-white/5">
          <button @click="showDiagnoseModal = false" class="bg-primary-600 hover:bg-primary-500 text-white font-bold text-sm px-6 py-2.5 rounded-2xl transition shadow-lg shadow-primary-500/20">关闭</button>
        </div>
      </div>
    </div>

  </div>
</template>
