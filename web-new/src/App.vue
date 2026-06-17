<script setup>
import { ref, onMounted, watch, provide } from 'vue'
import Header from './components/Header.vue'
import Dashboard from './components/Dashboard.vue'
import Mappings from './components/Mappings.vue'
import Forwards from './components/Forwards.vue'
import Settings from './components/Settings.vue'
import LoginModal from './components/LoginModal.vue'
import { useApi } from './composables/useApi'
import { useTheme } from './composables/useTheme'

const { isDark, toggleTheme } = useTheme()
const { apiGet, apiPost } = useApi()

// State
const activeTab = ref(localStorage.getItem('stealth_active_tab') || 'dashboard')
const isAuthenticated = ref(false)
const entries = ref([])
const exits = ref([])
const rules = ref([])
const mappings = ref([])
const portForwards = ref([])
const trafficStats = ref({})
const settings = ref({})

// Provide shared state to child components
provide('entries', entries)
provide('exits', exits)
provide('rules', rules)
provide('mappings', mappings)
provide('portForwards', portForwards)
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
      const [e, x, r, m, pf, t, s] = await Promise.all([
        apiGet('/api/v1/entries'),
        apiGet('/api/v1/exits'),
        apiGet('/api/v1/rules'),
        apiGet('/api/v1/mappings'),
        apiGet('/api/v1/portforwards'),
        apiGet('/api/v1/traffic'),
        apiGet('/api/v1/system/config')
      ])
      entries.value = e || []
      exits.value = x || []
      rules.value = r || []
      mappings.value = m || []
      portForwards.value = pf || []
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
  localStorage.removeItem('stealth_active_tab')
  isAuthenticated.value = false
  entries.value = []
  exits.value = []
  rules.value = []
  mappings.value = []
  portForwards.value = []
}

// Watch for tab changes to fetch settings and persist tab
watch(activeTab, (val) => {
  localStorage.setItem('stealth_active_tab', val)
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
  <div :class="{ 'dark': isDark }" class="min-h-screen transition-colors duration-300 flex flex-col md:flex-row bg-[var(--bg-primary)]">
    
    <!-- 左侧精美侧边栏 (在大屏显示，小屏隐藏) -->
    <aside class="hidden md:flex flex-col w-64 glass border-r border-white/5 p-6 h-screen sticky top-0 justify-between shrink-0">
      <div class="space-y-8">
        <!-- Logo -->
        <div class="px-2">
          <h1 class="text-2xl font-extrabold tracking-tighter flex items-baseline gap-2">
            <span class="gradient-text">Stealth</span>
            <span class="text-sm font-bold text-[#8b5cf6]">Forward</span>
          </h1>
          <p class="text-[var(--text-muted)] text-[0.7rem] mt-1">隐形中转分流中心</p>
        </div>
        
        <!-- 菜单列表 -->
        <nav class="space-y-2">
          <div
            @click="activeTab = 'dashboard'"
            :class="['flex items-center gap-3 px-4 py-3 rounded-2xl cursor-pointer transition text-sm font-medium', activeTab === 'dashboard' ? 'bg-primary-600/10 text-primary-400 border border-primary-500/20' : 'text-gray-400 hover:bg-white/5 hover:text-white']"
          >
            📊 节点概览
          </div>
          <div
            @click="activeTab = 'mappings'"
            :class="['flex items-center gap-3 px-4 py-3 rounded-2xl cursor-pointer transition text-sm font-medium', activeTab === 'mappings' ? 'bg-primary-600/10 text-primary-400 border border-primary-500/20' : 'text-gray-400 hover:bg-white/5 hover:text-white']"
          >
            ⚙️ 链路配置
          </div>
          <div
            @click="activeTab = 'forwards'"
            :class="['flex items-center gap-3 px-4 py-3 rounded-2xl cursor-pointer transition text-sm font-medium', activeTab === 'forwards' ? 'bg-primary-600/10 text-primary-400 border border-primary-500/20' : 'text-gray-400 hover:bg-white/5 hover:text-white']"
          >
            🔄 端口转发
          </div>
          <div
            @click="activeTab = 'settings'"
            :class="['flex items-center gap-3 px-4 py-3 rounded-2xl cursor-pointer transition text-sm font-medium', activeTab === 'settings' ? 'bg-primary-600/10 text-primary-400 border border-primary-500/20' : 'text-gray-400 hover:bg-white/5 hover:text-white']"
          >
            🛠️ 系统设置
          </div>
        </nav>
      </div>
      
      <!-- 底部版本 -->
      <div class="px-2 text-[var(--text-muted)] text-xs font-mono">
        Version v3.9.6
      </div>
    </aside>

    <!-- 移动端底栏导航 (在小屏显示，大屏隐藏) -->
    <nav class="md:hidden fixed bottom-4 left-4 right-4 glass p-2 rounded-2xl flex justify-around items-center z-40 border border-white/10 shadow-2xl">
      <div @click="activeTab = 'dashboard'" :class="['flex flex-col items-center p-2 rounded-xl text-xs transition', activeTab === 'dashboard' ? 'text-primary-400' : 'text-gray-500']">
        <span class="text-lg">📊</span>
        <span class="mt-0.5">概览</span>
      </div>
      <div @click="activeTab = 'mappings'" :class="['flex flex-col items-center p-2 rounded-xl text-xs transition', activeTab === 'mappings' ? 'text-primary-400' : 'text-gray-500']">
        <span class="text-lg">⚙️</span>
        <span class="mt-0.5">配置</span>
      </div>
      <div @click="activeTab = 'forwards'" :class="['flex flex-col items-center p-2 rounded-xl text-xs transition', activeTab === 'forwards' ? 'text-primary-400' : 'text-gray-500']">
        <span class="text-lg">🔄</span>
        <span class="mt-0.5">转发</span>
      </div>
      <div @click="activeTab = 'settings'" :class="['flex flex-col items-center p-2 rounded-xl text-xs transition', activeTab === 'settings' ? 'text-primary-400' : 'text-gray-500']">
        <span class="text-lg">🛠️</span>
        <span class="mt-0.5">系统</span>
      </div>
    </nav>

    <!-- 右侧主内容区 -->
    <main class="flex-1 p-4 md:p-8 overflow-y-auto max-w-full w-full pb-24 md:pb-8">
      <!-- Header -->
      <Header
        :isDark="isDark"
        @toggle-theme="toggleTheme"
        @refresh="fetchData"
        @logout="logout"
      />

      <!-- Stats Overview -->
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6 mb-8">
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
      <Forwards v-else-if="activeTab === 'forwards'" @refresh="fetchData" />
      <Settings v-else-if="activeTab === 'settings'" />
    </main>

    <!-- Login Modal -->
    <LoginModal v-if="!isAuthenticated" @login="handleLogin" />
  </div>
</template>
