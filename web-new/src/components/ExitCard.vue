<script setup>
import { computed, inject } from 'vue'
import { useApi } from '../composables/useApi'

const props = defineProps({
  exit: Object
})

const emit = defineEmits(['edit', 'refresh'])

const trafficStats = inject('trafficStats')
const { apiDelete } = useApi()

const config = computed(() => {
  try {
    return JSON.parse(props.exit.config)
  } catch {
    return {}
  }
})

// 计算该落地节点的总流量
const exitTraffic = computed(() => {
  if (!trafficStats.value || !trafficStats.value.exit_stats) return 0
  const stat = trafficStats.value.exit_stats[props.exit.id]
  return stat ? (stat.upload || 0) + (stat.download || 0) : 0
})

async function handleDelete() {
  if (!confirm('确定删除此落地节点?')) return
  try {
    await apiDelete(`/api/v1/exits/${props.exit.id}`)
    emit('refresh')
  } catch (e) {
    alert('删除失败: ' + e.message)
  }
}

function formatBytes(bytes) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

import { ref } from 'vue'
const clearingTraffic = ref(false)
async function clearTraffic() {
  if (!confirm('确定清除此落地节点的流量统计？此操作不可逆！')) return
  clearingTraffic.value = true
  try {
    await apiDelete(`/api/v1/traffic/exit/${props.exit.id}`)
    emit('refresh')
  } catch (e) {
    alert('清除失败: ' + e.message)
  } finally {
    clearingTraffic.value = false
  }
}
</script>

<template>
  <div class="glass p-5 rounded-3xl group border-l-4 border-emerald-500/30 shadow-lg hover:shadow-xl transition-shadow">
    <div class="flex justify-between items-start mb-3">
      <div>
        <div class="font-bold flex items-center gap-2">
          {{ exit.name }}
          <span class="bg-emerald-500/10 text-emerald-400 text-xs p-1 px-1.5 rounded uppercase">
            {{ exit.protocol }}
          </span>
        </div>
        <div class="text-xs text-[var(--text-muted)] mt-1 font-mono truncate max-w-[150px]">
          {{ config.server || config.address }}:{{ config.server_port || config.port }}
        </div>
      </div>
      
      <!-- Actions -->
      <div class="flex gap-1 md:opacity-0 md:group-hover:opacity-100 opacity-100 transition relative z-10">
        <button
          @click="$emit('edit', exit)"
          class="p-1.5 glass rounded-lg text-emerald-400 hover:scale-110 cursor-pointer"
          title="编辑"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"></path>
          </svg>
        </button>
        <button
          @click="handleDelete"
          class="p-1.5 glass rounded-lg text-rose-500 hover:scale-110 cursor-pointer"
          title="删除"
        >
          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
          </svg>
        </button>
      </div>
    </div>
    
    <div class="mt-4 flex items-center justify-between">
      <div class="text-[10px] text-[var(--text-muted)] uppercase tracking-tight">已用流量</div>
      <div class="flex items-center gap-2">
        <div class="text-xs font-mono font-bold text-emerald-400">
          {{ formatBytes(exitTraffic) }}
        </div>
        <button 
          @click="clearTraffic" 
          :disabled="clearingTraffic" 
          class="p-1 text-[var(--text-muted)] hover:text-rose-500 transition opacity-0 group-hover:opacity-50 hover:opacity-100"
          title="清除流量统计"
        >
          <svg class="w-3 h-3" :class="{'animate-spin': clearingTraffic}" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    </div>
  </div>
</template>
