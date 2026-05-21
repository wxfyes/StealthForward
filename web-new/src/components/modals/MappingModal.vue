<script setup>
import { ref, inject, onMounted } from 'vue'
import { useApi } from '../../composables/useApi'

const props = defineProps({
  mapping: Object
})

const emit = defineEmits(['close', 'saved'])

const entries = inject('entries')
const exits = inject('exits')
const { apiPost } = useApi()

const form = ref({
  id: null,
  entry_node_id: null,
  v2board_node_id: null,
  v2board_type: 'v2ray',
  target_exit_id: null,
  unlock_exit_id: null,
  unlock_domains: '',
  port: null
})

const saving = ref(false)

onMounted(() => {
  if (props.mapping) {
    form.value = { ...props.mapping }
  } else {
    // Set defaults
    if (entries.value.length > 0) form.value.entry_node_id = entries.value[0].id
    if (exits.value.length > 0) form.value.target_exit_id = exits.value[0].id
  }
})

async function handleSubmit() {
  if (!form.value.v2board_node_id) {
    alert('请填入 V2Board 节点 ID (例如 21)')
    return
  }
  if (!form.value.target_exit_id) {
    alert('请选择目标落地出口')
    return
  }
  
  saving.value = true
  
  const payload = {
    id: form.value.id,
    entry_node_id: parseInt(form.value.entry_node_id),
    v2board_node_id: parseInt(form.value.v2board_node_id),
    v2board_type: form.value.v2board_type || 'v2ray',
    target_exit_id: parseInt(form.value.target_exit_id),
    unlock_exit_id: form.value.unlock_exit_id ? parseInt(form.value.unlock_exit_id) : 0,
    unlock_domains: form.value.unlock_domains || '',
    port: form.value.port || 0
  }
  
  try {
    const url = '/api/v1/mappings' + (form.value.id ? '/' + form.value.id : '')
    await fetch(url, {
      method: form.value.id ? 'PUT' : 'POST',
      body: JSON.stringify(payload),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': localStorage.getItem('stealth_token') || ''
      }
    })
    emit('saved')
  } catch (e) {
    alert('保存失败: ' + e.message)
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4" @click.self="$emit('close')">
    <div class="glass w-full max-w-md p-8 rounded-3xl animate-slide-up">
      <h3 class="text-2xl font-bold mb-6">{{ mapping ? '编辑' : '新增' }}分流规则</h3>
      
      <div class="space-y-4 text-sm">
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          来源入口
          <select v-model.number="form.entry_node_id">
            <option v-for="e in entries" :key="e.id" :value="e.id">{{ e.name }}</option>
          </select>
        </label>
        
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          V2Board 节点 ID
          <input type="number" v-model.number="form.v2board_node_id" placeholder="例如: 21" />
        </label>
        
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          目标落地出口
          <select v-model.number="form.target_exit_id">
            <option v-for="ex in exits" :key="ex.id" :value="ex.id">{{ ex.name }}</option>
          </select>
        </label>
        
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          解锁落地出口 (可选)
          <select v-model.number="form.unlock_exit_id">
            <option :value="0">不启用解锁分流（全部走上方落地）</option>
            <option v-for="ex in exits" :key="ex.id" :value="ex.id">🔑 解锁分流：{{ ex.name }}</option>
          </select>
        </label>

        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          解锁域名后缀 (可选)
          <textarea 
            class="p-3 bg-white/5 border border-white/10 rounded-xl text-xs text-white" 
            v-model="form.unlock_domains" 
            rows="3" 
            placeholder="留空时默认解锁：OpenAI / Gemini / Claude&#10;用换行、空格或逗号分隔各个域名，如：&#10;gemini.google.com&#10;generativeai.google"
          ></textarea>
        </label>
        
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          协议类型
          <select v-model="form.v2board_type">
            <option value="v2ray">V2ray</option>
            <option value="vless">VLESS</option>
            <option value="shadowsocks">Shadowsocks</option>
            <option value="anytls">AnyTLS</option>
          </select>
        </label>
        
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          自定义端口 (可选)
          <input type="number" v-model.number="form.port" placeholder="留空则跟随入口默认" />
        </label>
      </div>
      
      <div class="flex gap-4 mt-8">
        <button @click="$emit('close')" class="flex-1 p-4 bg-[var(--bg-secondary)] rounded-2xl">取消</button>
        <button
          @click="handleSubmit"
          :disabled="saving"
          class="flex-1 p-4 bg-gradient-to-r from-primary-500 to-purple-600 rounded-2xl font-bold disabled:opacity-50"
        >
          {{ saving ? '保存中...' : '保存规则' }}
        </button>
      </div>
    </div>
  </div>
</template>
