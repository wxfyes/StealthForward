<script setup>
import { inject, ref } from 'vue'
import MappingModal from './modals/MappingModal.vue'
import { useApi } from '../composables/useApi'

const emit = defineEmits(['refresh'])

const entries = inject('entries')
const exits = inject('exits')
const mappings = inject('mappings')
const trafficStats = inject('trafficStats')
const { apiDelete } = useApi()

const showModal = ref(false)
const editingMapping = ref(null)

function findNodeName(list, id) {
  const items = list === 'entries' ? entries.value : exits.value
  const node = items.find(n => n.id === id)
  return node ? node.name : ''
}

function openAddMapping() {
  editingMapping.value = null
  showModal.value = true
}

function openEditMapping(m) {
  editingMapping.value = { ...m }
  showModal.value = true
}

async function handleDelete(id) {
  if (!confirm('确定删除此分流规则?')) return
  try {
    await apiDelete(`/api/v1/mappings/${id}`)
    emit('refresh')
  } catch (e) {
    alert('删除失败: ' + e.message)
  }
}

function handleSaved() {
  showModal.value = false
  emit('refresh')
}

// 计算该 Mapping 下的总流量
function getMappingTraffic(m) {
  if (!trafficStats.value || !trafficStats.value.user_stats) return 0
  
  let total = 0
  const prefix = `n${m.v2board_node_id}-`
  
  for (const [tag, stat] of Object.entries(trafficStats.value.user_stats)) {
    // 匹配特定节点的标签 (例如 n20-xxxxx)
    if (tag.startsWith(prefix)) {
      total += (stat.upload || 0) + (stat.download || 0)
    }
  }
  return total
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
</script>

<template>
  <div class="space-y-6 animate-fade-in">
    <div class="glass p-4 sm:p-8 rounded-3xl">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
        <div>
          <h2 class="text-2xl font-bold">多目标分流策略 (Routing Policy)</h2>
          <p class="text-[var(--text-muted)] text-sm">单入口 443 转发上百节点的"心脏" | 根据节点 ID 动态流转</p>
        </div>
        <button
          @click="openAddMapping"
          class="w-full sm:w-auto bg-gradient-to-r from-primary-500 to-purple-600 p-3 px-8 rounded-full text-sm font-bold shadow-lg shadow-primary-500/20 active:scale-95 transition text-white"
        >
          添加分流规则
        </button>
      </div>

      <!-- Table (PC only) -->
      <div class="hidden md:block overflow-hidden rounded-2xl border border-[var(--border-color)]">
        <table class="w-full text-left border-collapse">
          <thead class="bg-[var(--bg-secondary)] text-[var(--text-muted)] text-xs uppercase tracking-wider font-semibold">
            <tr>
              <th class="py-4 px-6">来源入口 (Entry)</th>
              <th class="py-4 px-6">V2B 节点 ID</th>
              <th class="py-4 px-6">目标分流 (Exit)</th>
              <th class="py-4 px-6">监听端口</th>
              <th class="py-4 px-6">已用流量</th>
              <th class="py-4 px-6">状态</th>
              <th class="py-4 px-6 text-right">操作</th>
            </tr>
          </thead>
          <tbody class="text-sm divide-y divide-[var(--border-color)]">
            <tr
              v-for="m in mappings"
              :key="m.id"
              class="hover:bg-primary-500/5 transition group"
            >
              <td class="py-4 px-6 font-medium">
                <div class="flex flex-col">
                  <span>{{ findNodeName('entries', m.entry_node_id) }}</span>
                  <span class="text-xs text-[var(--text-muted)]">Entry #{{ m.entry_node_id }}</span>
                </div>
              </td>
              <td class="py-4 px-6">
                <span class="inline-flex items-center px-2.5 py-1 rounded-md bg-[var(--bg-secondary)] text-primary-400 text-xs font-mono border border-primary-500/20">
                  Node {{ m.v2board_node_id }}
                </span>
              </td>
              <td class="py-4 px-6">
                <div class="flex items-center gap-2">
                  <div class="w-2 h-2 rounded-full bg-emerald-500"></div>
                  <span class="text-emerald-400">{{ findNodeName('exits', m.target_exit_id) }}</span>
                </div>
              </td>
              <td class="py-4 px-6">
                <span v-if="m.port > 0" class="font-mono text-amber-400 bg-amber-500/10 px-2 py-1 rounded border border-amber-500/20">
                  {{ m.port }}
                </span>
                <span v-else class="text-[var(--text-muted)] text-xs italic">跟随入口</span>
              </td>
              <td class="py-4 px-6">
                <span class="font-mono text-primary-400 font-bold">
                  {{ formatBytes(getMappingTraffic(m)) }}
                </span>
              </td>
              <td class="py-4 px-6">
                <span class="inline-flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
                  <span class="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
                  运行中
                </span>
              </td>
              <td class="py-4 px-6 text-right">
                <div class="flex justify-end gap-2 md:opacity-0 md:group-hover:opacity-100 opacity-100 transition duration-200">
                  <button
                    @click="openEditMapping(m)"
                    class="p-2 bg-primary-500/10 text-primary-400 rounded-lg hover:bg-primary-500 hover:text-white transition"
                    title="编辑"
                  >
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                    </svg>
                  </button>
                  <button
                    @click="handleDelete(m.id)"
                    class="p-2 bg-rose-500/10 text-rose-500 rounded-lg hover:bg-rose-500 hover:text-white transition"
                    title="删除"
                  >
                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="mappings.length === 0">
              <td colspan="7" class="py-12 text-center text-[var(--text-muted)] italic">
                暂无分流策略，所有流量将默认转发至入口绑定的落地机。
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Mobile Card List (Mobile only) -->
      <div class="block md:hidden space-y-4">
        <div v-for="m in mappings" :key="m.id" class="p-5 bg-[var(--bg-secondary)]/50 backdrop-blur-md rounded-2xl border border-[var(--border-color)] space-y-3">
          <div class="flex justify-between items-center pb-2 border-b border-white/5">
            <div class="flex flex-col">
              <span class="font-bold text-white">{{ findNodeName('entries', m.entry_node_id) }}</span>
              <span class="text-[10px] text-[var(--text-muted)]">入口 ID #{{ m.entry_node_id }}</span>
            </div>
            <span class="inline-flex items-center px-2.5 py-0.5 rounded-md bg-primary-500/10 text-primary-400 text-xs font-mono border border-primary-500/20">
              V2B ID: {{ m.v2board_node_id }}
            </span>
          </div>
          
          <div class="grid grid-cols-2 gap-y-2 gap-x-4 text-xs pt-1">
            <div class="flex flex-col">
              <span class="text-[var(--text-muted)] text-[10px] uppercase">目标分流 (Exit)</span>
              <span class="text-emerald-400 font-medium truncate mt-0.5">{{ findNodeName('exits', m.target_exit_id) }}</span>
            </div>
            <div class="flex flex-col">
              <span class="text-[var(--text-muted)] text-[10px] uppercase">监听端口</span>
              <span class="text-amber-400 font-mono font-medium mt-0.5">{{ m.port > 0 ? m.port : '跟随入口' }}</span>
            </div>
            <div class="flex flex-col">
              <span class="text-[var(--text-muted)] text-[10px] uppercase">已用流量</span>
              <span class="text-primary-400 font-mono font-bold mt-0.5">{{ formatBytes(getMappingTraffic(m)) }}</span>
            </div>
            <div class="flex flex-col">
              <span class="text-[var(--text-muted)] text-[10px] uppercase">状态</span>
              <span class="text-emerald-500 mt-0.5">● 运行中</span>
            </div>
          </div>
          
          <div class="flex justify-end gap-2 pt-2 border-t border-white/5">
            <button
              @click="openEditMapping(m)"
              class="px-4 py-2 bg-primary-500/10 text-primary-400 rounded-xl text-xs font-bold hover:bg-primary-500 hover:text-white transition flex-1 text-center justify-center"
            >
              编辑
            </button>
            <button
              @click="handleDelete(m.id)"
              class="px-4 py-2 bg-rose-500/10 text-rose-500 rounded-xl text-xs font-bold hover:bg-rose-500 hover:text-white transition flex-1 text-center justify-center"
            >
              删除
            </button>
          </div>
        </div>
        <div v-if="mappings.length === 0" class="py-12 text-center text-[var(--text-muted)] italic text-sm">
          暂无分流策略，所有流量将默认转发至入口绑定的落地机。
        </div>
      </div>
    </div>

    <!-- Modal -->
    <MappingModal
      v-if="showModal"
      :mapping="editingMapping"
      @close="showModal = false"
      @saved="handleSaved"
    />
  </div>
</template>
