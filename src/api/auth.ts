import request from '@/utils/http'

const AUTH_API_PREFIX = '/api/v1/auths'

const getFrontendRoles = (role: string): string[] => {
  if (role === 'admin') return ['R_SUPER', 'R_ADMIN']
  if (role === 'user') return ['R_USER']
  return []
}

const getFrontendButtons = (role: string): string[] =>
  role === 'admin' ? ['add', 'edit', 'delete'] : []

const toUserInfo = (session: Api.Auth.LoginResponse): Api.Auth.UserInfo => ({
  userId: session.id,
  userName: session.name,
  email: session.email,
  avatar: session.profile_image_url,
  roles: getFrontendRoles(session.role),
  buttons: getFrontendButtons(session.role)
})

/**
 * 登录
 * @param params 登录参数
 * @returns 登录响应
 */
export function fetchLogin(params: Api.Auth.LoginParams) {
  const email = params.email?.trim()
  const username = params.username?.trim()
  const identity = email ? { email } : username?.includes('@') ? { email: username } : { username }

  return request.post<Api.Auth.LoginResponse>({
    url: `${AUTH_API_PREFIX}/signin`,
    params: {
      ...identity,
      password: params.password
    }
  })
}

/**
 * 获取用户信息
 * @returns 用户信息
 */
export async function fetchGetUserInfo(): Promise<Api.Auth.UserInfo> {
  const session = await request.get<Api.Auth.LoginResponse>({
    url: `${AUTH_API_PREFIX}/`
  })
  return toUserInfo(session)
}

/**
 * 注销后端 Session
 */
export function fetchLogout() {
  return request.post<{ status: boolean }>({
    url: `${AUTH_API_PREFIX}/signout`
  })
}
