<script setup>
import { ref, onMounted, watch, provide } from 'vue'
import Header from './components/Header.vue'
import Dashboard from './components/Dashboard.vue'
import Mappings from './components/Mappings.vue'
import Settings from './components/Settings.vue'
import LoginModal from './components/LoginModal.vue'
import { useApi } from './composables/useApi'
import { useTheme } from './composables/useTheme'

const { isDark, toggleTheme } = useTheme()
const { apiGet, apiPost } = useApi()

// State
const activeTab = ref('dashboard')
const isAuthenticated = ref(false)
const entries = ref([])
const exits = ref([])
const rules = ref([])
const mappings = ref([])
const trafficStats = ref({})
const settings = ref({})

// Provide shared state to child components
provide('entries', entries)
provide('exits', exits)
provide('rules', rules)
provide('mappings', mappings)
provide('trafficStats', trafficStats)
provide('settings', settings)
provide('apiGet', apiGet)
provide('apiPost', apiPost)

// Refresh interval
const refreshTimer = ref(null)

// Check auth on mount
onMounted(() => {
  const token = localStorage.getItem('stealth_token')
  if (token) {
    isAuthenticated.value = true
    fetchData()
    startPolling()
  }
})

function startPolling() {
  if (refreshTimer.value) clearInterval(refreshTimer.value)
  // 3秒自动刷新一次数据，让探针和网速在网页端实时跳动
  refreshTimer.value = setInterval(() => {
    if (isAuthenticated.value && activeTab.value === 'dashboard') {
      fetchData(true) // true 表示静默刷新，不显示加载状态
    }
  }, 3000)
}

// Fetch all data
async function fetchData(silent = false) {
  if (!isAuthenticated.value) return
  
  try {
    if (silent) {
      // 定时轮询只拉取实时流量与探针状态，不重复拉取静态配置（节点和规则）
      const t = await apiGet('/api/v1/traffic')
      trafficStats.value = t || {}
    } else {
      // 首次加载或手动刷新全量拉取
      const [e, x, r, m, t, s] = await Promise.all([
        apiGet('/api/v1/entries'),
        apiGet('/api/v1/exits'),
        apiGet('/api/v1/rules'),
        apiGet('/api/v1/mappings'),
        apiGet('/api/v1/traffic'),
        apiGet('/api/v1/system/config')
      ])
      entries.value = e || []
      exits.value = x || []
      rules.value = r || []
      mappings.value = m || []
      trafficStats.value = t || {}
      if (s && s.config) settings.value = s.config
    }
  } catch (err) {
    if (err.message?.includes('401')) {
      logout()
    }
    console.error('Data fetch failed:', err)
  }
}

function handleLogin() {
  isAuthenticated.value = true
  fetchData()
  startPolling()
}

function logout() {
  if (refreshTimer.value) clearInterval(refreshTimer.value)
  localStorage.removeItem('stealth_token')
  isAuthenticated.value = false
  entries.value = []
  exits.value = []
  rules.value = []
  mappings.value = []
}

// Watch for tab changes to fetch settings
watch(activeTab, (val) => {
  if (val === 'settings') {
    fetchSettings()
  }
})

async function fetchSettings() {
  try {
    const res = await apiGet('/api/v1/system/config')
    if (res.config) settings.value = res.config
  } catch (err) {
    console.error('Settings fetch failed:', err)
  }
}
</script>

<template>
  <div :class="{ 'dark': isDark }" class="min-h-screen transition-colors duration-300">
    <div class="p-4 md:p-8 max-w-7xl mx-auto">
      <!-- Header -->
      <Header
        v-model:activeTab="activeTab"
        :isDark="isDark"
        @toggle-theme="toggleTheme"
        @refresh="fetchData"
        @logout="logout"
      />

      <!-- Stats Overview -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
        <div class="glass p-5 rounded-3xl">
          <div class="text-sm font-medium text-[var(--text-muted)] uppercase tracking-wide mb-1">入口节点</div>
          <div class="text-3xl font-light">{{ entries.length }} <span class="text-xs text-primary-400">Active</span></div>
        </div>
        <div class="glass p-5 rounded-3xl">
          <div class="text-sm font-medium text-[var(--text-muted)] uppercase tracking-wide mb-1">分流出口</div>
          <div class="text-3xl font-light">{{ exits.length }} <span class="text-xs text-emerald-400">Nodes</span></div>
        </div>
        <div class="glass p-5 rounded-3xl">
          <div class="text-sm font-medium text-[var(--text-muted)] uppercase tracking-wide mb-1">映射规则</div>
          <div class="text-3xl font-light text-primary-400">{{ mappings.length }} <span class="text-xs text-[var(--text-muted)]">Fixed</span></div>
        </div>
        <div class="glass p-5 rounded-3xl">
          <div class="text-sm font-medium text-primary-400 uppercase tracking-wide mb-1">总链路数</div>
          <div class="text-3xl font-light">{{ rules.length + mappings.length }}</div>
        </div>
      </div>

      <!-- Main Content -->
      <Dashboard v-if="activeTab === 'dashboard'" @refresh="fetchData" />
      <Mappings v-else-if="activeTab === 'mappings'" @refresh="fetchData" />
      <Settings v-else-if="activeTab === 'settings'" />
    </div>

    <!-- Login Modal -->
    <LoginModal v-if="!isAuthenticated" @login="handleLogin" />
  </div>
</template>
