/**
 * 认证工具函数
 * 统一处理认证相关的逻辑
 */

import { useAuthStore } from '@/stores/auth'
import router from '@/router'
import { ElMessage } from 'element-plus'

/**
 * 检查是否是认证错误
 */
export const isAuthError = (error: any): boolean => {
  if (!error) return false

  // 检查 HTTP 状态码
  if (error.response?.status === 401) {
    return true
  }

  // 检查业务错误码
  const code = error.code || error.response?.data?.code
  if (code === 401 || code === 40101 || code === 40102 || code === 40103) {
    return true
  }

  // 检查错误消息
  const message = error.message || error.response?.data?.message || ''
  const authKeywords = [
    '认证失败',
    '登录已过期',
    '未授权',
    'unauthorized',
    'token',
    'Token',
    'TOKEN',
    '请重新登录'
  ]

  return authKeywords.some(keyword => message.includes(keyword))
}

/**
 * 处理认证错误
 * 清除认证信息并跳转到登录页
 */
export const handleAuthError = (error?: any, showMessage = true): void => {
  console.log('🔒 处理认证错误:', error)

  const authStore = useAuthStore()

  // 清除认证信息
  authStore.clearAuthInfo()

  // 显示错误消息
  if (showMessage) {
    const message = error?.message || error?.response?.data?.message || '登录已过期，请重新登录'
    ElMessage.error(message)
  }

  // 跳转到登录页
  const currentPath = router.currentRoute.value.fullPath
  if (currentPath !== '/login') {
    // 保存当前路径，登录后跳转回来
    authStore.setRedirectPath(currentPath)
    router.push('/login')
  }
}


export interface ParsedToken {
  ident: string
  exp: string        // RFC3339 string
  expDate: Date
}

/**
 * 检查 token 是否有效
 */
export const isTokenValid = (token: string | null): boolean => {
  if (!token) return false

  // mock token（开发环境）
  if (token === 'mock-token' || token.startsWith('mock-')) {
    console.warn('⚠️ mock token')
    return false
  }

  const parsed = parseToken(token)
  if (!parsed) return false

  const now = Date.now()
  if (parsed.expDate.getTime() <= now) {
    console.warn('⚠️ Token 已过期')
    return false
  }

  return true
}


const base64UrlDecode = (input: string): string => {
  // base64url → base64
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=')
  return atob(padded)
}

/**
 * 从 token 中提取用户信息
 */
export const parseToken = (token: string): ParsedToken | null => {
  if (!token || typeof token !== 'string') return null

  const parts = token.split('.')
  if (parts.length !== 3) return null

  try {
    const ident = base64UrlDecode(parts[0])
    const expStr = base64UrlDecode(parts[1])
    const expDate = new Date(expStr)

    if (isNaN(expDate.getTime())) {
      console.warn('⚠️ exp 不是有效时间:', expStr)
      return null
    }

    return {
      ident,
      exp: expStr,
      expDate,
    }
  } catch (e) {
    console.warn('⚠️ Token 解析失败:', e)
    return null
  }
}

/**
 * 获取 token 剩余有效时间（秒）
 */
export const getTokenRemainingTime = (token: string): number => {
  const parsed = parseToken(token)
  if (!parsed) return 0

  const remainingMs = parsed.expDate.getTime() - Date.now()
  return Math.max(0, Math.floor(remainingMs / 1000))
}


/**
 * 检查 token 是否即将过期（默认 5 分钟）
 */
export const isTokenExpiringSoon = (token: string, thresholdSeconds = 300): boolean => {
  const remaining = getTokenRemainingTime(token)
  return remaining > 0 && remaining < thresholdSeconds
}

/**
 * 自动刷新 token（如果即将过期）
 */
export const autoRefreshToken = async (): Promise<boolean> => {
  const authStore = useAuthStore()

  if (!authStore.token) {
    return false
  }

  // 检查 token 是否即将过期
  if (isTokenExpiringSoon(authStore.token)) {
    console.log('🔄 Token 即将过期，自动刷新...')
    try {
      const success = await authStore.refreshAccessToken()
      if (success) {
        console.log('✅ Token 自动刷新成功')
        return true
      } else {
        console.log('❌ Token 自动刷新失败')
        return false
      }
    } catch (error) {
      console.error('❌ Token 自动刷新异常:', error)
      return false
    }
  }

  return true
}

/**
 * 设置定时刷新 token
 */
export const setupTokenRefreshTimer = (): void => {
  // 每分钟检查一次
  setInterval(() => {
    autoRefreshToken()
  }, 60000)

  console.log('✅ Token 自动刷新定时器已启动')
}

