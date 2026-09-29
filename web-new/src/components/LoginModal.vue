<script setup>
import { ref, computed } from 'vue'

const emit = defineEmits(['login'])

// 表单字段
const username = ref('admin')
const password = ref('')
const error = ref('')
const loading = ref(false)

// 处理登录
async function handleLogin() {
  loading.value = true
  error.value = ''
  
  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        username: username.value, 
        password: password.value 
      })
    })

    
    const data = await res.json()
    
    if (!res.ok) {
      throw new Error(data.error || '验证失败')
    }
    
    // 保存登录信息
    localStorage.setItem('stealth_token', data.token)
    localStorage.setItem('stealth_role', data.role || 'user')
    localStorage.setItem('stealth_level', data.level || 'basic')
    if (data.expires_at) {
      localStorage.setItem('stealth_expires', data.expires_at)
    }
    
    emit('login')
  } catch (e) {
    error.value = e.message || '登录失败'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="fixed inset-0 bg-[var(--bg-primary)] z-50 flex items-center justify-center p-4 animate-fade-in">
    <div class="w-full max-w-md space-y-8">
        <!-- Logo -->
        <div class="text-center">
          <h1 class="text-5xl font-extrabold tracking-tighter gradient-text mb-2">StealthForward</h1>
          <p class="text-[var(--text-muted)]">商业化智能中转控制系统</p>
        </div>
        
        <!-- Login Form -->
        <div class="glass p-8 rounded-3xl space-y-6">
          
          <!-- Admin Input -->
          <div class="space-y-4">
            <div>
               <label class="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest pl-1">用户名</label>
               <input type="text" v-model="username" class="w-full mt-1 p-3 rounded-xl bg-black/20 border border-white/10 text-white" />
            </div>
            <div>
               <label class="text-xs font-bold text-[var(--text-muted)] uppercase tracking-widest pl-1">密码</label>
               <input type="password" v-model="password" @keyup.enter="handleLogin" class="w-full mt-1 p-3 rounded-xl bg-black/20 border border-white/10 text-white" placeholder="默认: admin" />
            </div>
          </div>
        
        <button
          @click="handleLogin"
          :disabled="loading"
          :class="[
            'w-full p-4 rounded-xl font-bold transition shadow-lg active:scale-95 disabled:opacity-50',
            'w-full p-4 rounded-xl font-bold transition shadow-lg active:scale-95 disabled:opacity-50 bg-primary-600 hover:bg-primary-500 shadow-primary-500/20'
          ]"
        >
          {{ loading ? '登录中...' : '进入控制台' }}
        </button>
        
        <p v-if="error" class="text-center text-rose-500 text-sm animate-pulse">
          {{ error }}
        </p>
      </div>
      
      <!-- Footer -->
      <p class="text-center text-xs text-[var(--text-muted)]/50">
        StealthForward v3.9.23 · Commercial License System
      </p>
    </div>
  </div>
</template>
