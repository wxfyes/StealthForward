<script setup>
import { ref, onMounted } from 'vue'
import { useApi } from '../../composables/useApi'

const props = defineProps({
  exit: Object
})

const emit = defineEmits(['close', 'saved'])

const { apiPost } = useApi()

const form = ref({
  id: null,
  name: '',
  protocol: 'ss',
  server: '',
  server_port: null,
  password: '',
  username: '',
  method: '2022-blake3-aes-128-gcm'
})

const saving = ref(false)

onMounted(() => {
  if (props.exit) {
    form.value = { ...props.exit }
    try {
      const config = JSON.parse(props.exit.config)
      form.value.server = config.server
      form.value.server_port = config.server_port
      form.value.password = config.password || config.uuid
      form.value.username = config.username || ''
      form.value.method = config.method || config.cipher || '2022-blake3-aes-128-gcm'
    } catch {}
  }
})

async function handleSubmit() {
  saving.value = true
  
  const config = {
    server: form.value.server,
    server_port: form.value.server_port,
    method: form.value.method
  }
  
  if (form.value.protocol === 'ss') {
    config.password = form.value.password
    config.cipher = form.value.method
  } else if (form.value.protocol === 'socks5' || form.value.protocol === 'http') {
    config.username = form.value.username
    config.password = form.value.password
  } else {
    config.uuid = form.value.password
  }
  
  try {
    await apiPost('/api/v1/exits', {
      id: form.value.id,
      name: form.value.name,
      protocol: form.value.protocol,
      config: JSON.stringify(config)
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
      <h3 class="text-2xl font-bold mb-6">{{ exit ? '编辑' : '新增' }}落地节点</h3>
      
      <div class="space-y-4 text-sm">
        <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          显示名称
          <input v-model="form.name" placeholder="香港 01 / 新加坡出口" />
        </label>
        
          <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
            协议
            <select v-model="form.protocol">
              <option value="ss">Shadowsocks (AEAD / 2022)</option>
              <option value="socks5">SOCKS5</option>
              <option value="http">HTTP Proxy</option>
              <option value="vmess">VMess</option>
              <option value="vless">VLESS</option>
            </select>
          </label>
        
        <div class="grid grid-cols-2 gap-4">
          <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
            服务器地址
            <input v-model="form.server" placeholder="1.2.3.4" />
          </label>
          <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
            端口
            <input type="number" v-model.number="form.server_port" placeholder="8388" />
          </label>
        </div>
        
          <label class="flex flex-col gap-1.5 text-[var(--text-muted)]">
            {{ form.protocol === 'ss' || form.protocol === 'socks5' || form.protocol === 'http' ? '密码 (Password)' : 'UUID' }}
            <input v-model="form.password" type="password" placeholder="Secret..." />
          </label>

          <label v-if="form.protocol === 'socks5' || form.protocol === 'http'" class="flex flex-col gap-1.5 text-[var(--text-muted)]">
            用户名 (Username)
            <input v-model="form.username" placeholder="Optional..." />
          </label>
        
        <label v-if="form.protocol === 'ss'" class="flex flex-col gap-1.5 text-[var(--text-muted)]">
          加密方法
          <select v-model="form.method">
            <!-- 经典 AEAD -->
            <option value="aes-128-gcm">aes-128-gcm</option>
            <option value="aes-256-gcm">aes-256-gcm</option>
            <option value="chacha20-ietf-poly1305">chacha20-ietf-poly1305</option>
            <option value="xchacha20-ietf-poly1305">xchacha20-ietf-poly1305</option>
            
            <!-- 2022 -->
            <option value="2022-blake3-aes-128-gcm">2022-blake3-aes-128-gcm</option>
            <option value="2022-blake3-aes-256-gcm">2022-blake3-aes-256-gcm</option>
            <option value="2022-blake3-chacha20-poly1305">2022-blake3-chacha20-poly1305</option>
            
            <!-- 其他 -->
            <option value="none">none</option>
          </select>
        </label>
      </div>
      
      <div class="flex gap-4 mt-8">
        <button @click="$emit('close')" class="flex-1 p-4 bg-[var(--bg-secondary)] rounded-2xl">取消</button>
        <button
          @click="handleSubmit"
          :disabled="saving"
          class="flex-1 p-4 bg-emerald-600 rounded-2xl font-bold disabled:opacity-50"
        >
          {{ saving ? '保存中...' : '保存节点' }}
        </button>
      </div>
    </div>
  </div>
</template>
