<script setup>
import { inject, ref, onMounted, watch } from 'vue'
import { useApi } from '../composables/useApi'

const settings = inject('settings')
const { apiPost, apiGet, apiPut, apiDelete } = useApi()

const saving = ref(false)
const loaded = ref(false)
const cloudAccounts = ref([])
const sshKeys = ref([])
const files = ref([]) // 对应之前的 keys 变量 (实体文件)

// 综合检查配置是否已经填充
function checkLoaded() {
  if (settings && settings.value && Object.keys(settings.value).length > 0) {
    loaded.value = true
  }
}

onMounted(async () => {
  checkLoaded()
  await Promise.all([
    fetchCloudAccounts(),
    fetchSSHKeys(),
    fetchFiles()
  ])
})

// 深度监听，一旦数据回来立即开门
watch(settings, () => {
  checkLoaded()
}, { deep: true })

async function fetchCloudAccounts() {
  try {
    cloudAccounts.value = await apiGet('/api/v1/cloud/accounts')
  } catch (e) { console.error(e) }
}

async function fetchSSHKeys() {
  try {
    sshKeys.value = await apiGet('/api/v1/system/ssh-keys')
  } catch (e) { console.error(e) }
}

async function fetchFiles() {
  try {
    const res = await apiGet('/api/v1/cloud/keys')
    files.value = res || []
  } catch (e) {
    console.error('获取密钥列表失败', e)
    files.value = []
  }
}

async function addCloudAccount() {
  const name = prompt('请输入账号备注名 (如: AWS-MyAcc-1)')
  if (!name) return
  try {
    await apiPost('/api/v1/cloud/accounts', { name, provider: 'aws', enabled: true })
    await fetchCloudAccounts()
  } catch (e) { alert(e.message) }
}

async function removeCloudAccount(id) {
  if (!confirm('确定删除此账号?')) return
  try {
    await apiDelete(`/api/v1/cloud/accounts/${id}`)
    await fetchCloudAccounts()
  } catch (e) { alert(e.message) }
}

async function saveAccount(acc) {
  try {
    await apiPut(`/api/v1/cloud/accounts/${acc.id}`, acc)
    alert('账号信息已更新')
  } catch (e) { alert('更新失败: ' + e.message) }
}

async function saveSSHKey(sk) {
  try {
    await apiPut(`/api/v1/system/ssh-keys/${sk.id}`, sk)
    alert('SSH 密钥已更新')
  } catch (e) { alert('更新失败: ' + e.message) }
}

async function saveSettings() {
  saving.value = true
  try {
    await apiPost('/api/v1/system/config', settings.value)
    alert('配置已保存')
  } catch (e) {
    alert('保存失败: ' + e.message)
  } finally {
    saving.value = false
  }
}

function downloadKey(name) {
  const token = localStorage.getItem('stealth_token')
  window.open(`/api/v1/cloud/keys/${name}?token=${token}`, '_blank')
}

function formatSize(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
</script>

<template>
  <div class="max-w-4xl mx-auto space-y-6 animate-fade-in pb-12">
    <!-- Cloud Account Pool -->
    <div class="glass p-8 rounded-3xl" v-if="loaded">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-2xl font-bold flex items-center gap-2" style="color: var(--text-primary)">
          <svg class="w-6 h-6 text-primary-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
          </svg>
          云平台账号池 (Account Pool)
        </h2>
        <button @click="addCloudAccount" class="p-2 px-4 bg-primary-500/10 text-primary-500 rounded-xl hover:bg-primary-500 hover:text-white transition text-sm font-bold flex items-center gap-1">
          <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" /></svg>
          添加账号
        </button>
      </div>

      <div class="space-y-4">
        <div v-for="acc in cloudAccounts" :key="acc.id" class="p-4 bg-[var(--bg-secondary)] rounded-2xl border border-[var(--border-color)] space-y-4">
          <div class="flex justify-between items-center">
            <div class="flex items-center gap-3">
              <span class="px-2 py-0.5 bg-primary-500 text-white text-[10px] font-bold rounded uppercase">{{ acc.provider }}</span>
              <span class="font-bold text-[var(--text-primary)]">{{ acc.name }}</span>
            </div>
            <button @click="removeCloudAccount(acc.id)" class="text-rose-500 hover:bg-rose-500/10 p-2 rounded-lg transition">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" /></svg>
            </button>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <label class="block text-xs text-[var(--text-muted)]">
              Access Key ID / Token
              <input v-model="acc.access_key" class="w-full mt-1 bg-black/5" />
            </label>
            <label class="block text-xs text-[var(--text-muted)]">
              Secret Key
              <input v-model="acc.secret_key" type="password" class="w-full mt-1 bg-black/5" />
            </label>
          </div>
          <div class="flex justify-end gap-2">
            <button @click="saveAccount(acc)" class="text-xs bg-primary-500/10 text-primary-500 px-3 py-1.5 rounded-lg hover:bg-primary-500 hover:text-white transition">更新保存</button>
          </div>
        </div>
        <div v-if="cloudAccounts.length === 0" class="text-center py-8 text-[var(--text-muted)] italic text-sm">
          暂无账号，点右上角添加。
        </div>
      </div>
    </div>

    <!-- Global System Config -->
    <div class="glass p-8 rounded-3xl" v-if="loaded">
      <h2 class="text-2xl font-bold mb-6 flex items-center gap-2" style="color: var(--text-primary)">
        <svg class="w-6 h-6 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
        </svg>
        基础环境配置 (Base Config)
      </h2>
      
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="space-y-4">
          <h3 class="text-sm font-bold text-amber-500 uppercase tracking-widest">AWS Defaults</h3>
          <label class="block text-sm text-[var(--text-muted)]">
            Default Region
            <select v-model="settings['aws.default_region']" class="w-full mt-1">
              <option value="ap-northeast-1">Tokyo (ap-northeast-1)</option>
              <option value="ap-east-1">Hong Kong (ap-east-1)</option>
              <option value="ap-southeast-1">Singapore (ap-southeast-1)</option>
              <option value="us-west-1">California (us-west-1)</option>
            </select>
          </label>
        </div>
        
        <div class="space-y-4">
          <h3 class="text-sm font-bold text-blue-500 uppercase tracking-widest">Cloudflare Defaults</h3>
          <label class="block text-sm text-[var(--text-muted)]">
            API Token (Global Backup)
            <input v-model="settings['cloudflare.api_token']" type="password" class="w-full mt-1" />
          </label>
          <label class="block text-sm text-[var(--text-muted)]">
            Default Zone
            <input v-model="settings['cloudflare.default_zone']" class="w-full mt-1" />
          </label>
        </div>

        <div class="space-y-4">
          <h3 class="text-sm font-bold text-rose-500 uppercase tracking-widest">Security</h3>
          <label class="block text-sm text-[var(--text-muted)]">
            Admin Password (面板登录密码)
            <input v-model="settings['system.admin_password']" type="password" class="w-full mt-1" placeholder="留空则沿用环境变量或默认密码" />
          </label>
          <label class="block text-sm text-[var(--text-muted)] mt-4">
            Communication Token (Agent 通信密钥)
            <div class="flex gap-2">
              <input v-model="settings['system.communication_token']" class="w-full font-mono text-indigo-500" readonly />
              <button @click="() => { settings['system.communication_token'] = Math.random().toString(36).substring(2,10) + Math.random().toString(36).substring(2,10) }" class="text-[10px] bg-rose-500/10 text-rose-500 px-2 rounded-lg">重置</button>
            </div>
            <p class="text-[10px] text-rose-400 mt-1 italic">提示：给 Agent 使用这个密钥。修改上面的登录密码不会导致 Agent 断联。</p>
          </label>
        </div>
      </div>
      
      <div class="mt-8 flex justify-end gap-3">
         <button @click="saveSettings" :disabled="saving" class="bg-primary-600 hover:bg-primary-500 disabled:opacity-50 text-white px-8 py-3 rounded-xl font-bold transition shadow-lg shadow-primary-500/20 active:scale-95">
          {{ saving ? '保存中...' : '保存系统配置' }}
        </button>
      </div>
    </div>

    <!-- Automated Provisioning SSH Keys -->
    <div class="glass p-8 rounded-3xl mt-6" v-if="loaded">
      <div class="flex justify-between items-center mb-6">
        <h2 class="text-xl font-bold flex items-center gap-2" style="color: var(--text-primary)">
          <svg class="w-5 h-5 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
          </svg>
          自动化部署密钥 (Provisioning SSH)
        </h2>
        <button @click="() => apiPost('/api/v1/system/ssh-keys', { name: 'new-key', user: 'root' }).then(fetchSSHKeys)" class="text-xs text-indigo-500 hover:bg-indigo-500/10 p-2 rounded-lg transition font-bold">+ 新增密钥</button>
      </div>

      <div class="space-y-4">
        <div v-for="sk in sshKeys" :key="sk.id" class="p-4 bg-[var(--bg-secondary)] rounded-2xl border border-[var(--border-color)]">
           <div class="flex justify-between items-center mb-4">
             <div class="flex items-center gap-2">
               <input v-model="sk.name" class="font-bold bg-transparent border-none p-0 w-32 focus:ring-0" />
               <input v-model="sk.user" class="text-xs text-[var(--text-muted)] bg-black/5 px-2 py-0.5 rounded border-none w-20" placeholder="user" />
             </div>
             <button @click="() => apiDelete(`/api/v1/system/ssh-keys/${sk.id}`).then(fetchSSHKeys)" class="text-rose-500 p-1 hover:bg-rose-500/10 rounded">
               <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg>
             </button>
           </div>
           <textarea v-model="sk.key_content" rows="3" class="w-full text-[10px] font-mono bg-black/20 border-none rounded-xl" placeholder="-----BEGIN RSA PRIVATE KEY-----"></textarea>
           <div class="mt-2 flex justify-end">
             <button @click="saveSSHKey(sk)" class="text-[10px] bg-indigo-500/10 text-indigo-500 px-3 py-1 rounded-lg hover:bg-indigo-500 hover:text-white transition">保存私钥内容</button>
           </div>
        </div>
      </div>
    </div>

    <!-- Generated EC2 Keys (Read Only List) -->
    <div class="glass p-8 rounded-3xl mt-6" v-if="loaded">
      <h2 class="text-xl font-bold mb-6 flex items-center gap-2" style="color: var(--text-primary)">
        <svg class="w-5 h-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7v8a2 2 0 002 2h6M8 7V5a2 2 0 012-2h4.586a1 1 0 01.707.293l4.414 4.414a1 1 0 01.293.707V15a2 2 0 01-2 2h-2M8 7H6a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2v-2" />
        </svg>
        存量实例证书 (.pem 存档)
      </h2>

      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div v-for="key in files" :key="key.name" class="p-4 bg-[var(--bg-secondary)] rounded-2xl border border-[var(--border-color)] flex justify-between items-center group hover:border-amber-500/30 transition">
          <div class="overflow-hidden">
            <div class="text-sm font-bold truncate pr-2 text-amber-500">{{ key.name }}</div>
            <div class="text-[10px] text-[var(--text-muted)] mt-1">
              {{ formatSize(key.size) }} | {{ key.updated_at }}
            </div>
          </div>
          <button @click="downloadKey(key.name)" class="p-2 bg-amber-500/10 text-amber-400 rounded-lg hover:bg-amber-500 hover:text-white transition shadow-sm border-none cursor-pointer">
            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a2 2 0 002 2h12a2 2 0 002-2v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
          </button>
        </div>
        <div v-if="files.length === 0" class="md:col-span-2 py-8 text-center text-[var(--text-muted)] italic text-sm">
          暂无本地保存的密钥文件。
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-else class="glass p-12 rounded-3xl flex flex-col items-center justify-center text-[var(--text-muted)] italic">
      <svg class="w-10 h-10 mb-4 animate-spin opacity-20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
      </svg>
      正在连接主控获取系统配置...
    </div>
  </div>
</template>
