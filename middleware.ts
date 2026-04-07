import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server'
import { NextRequest, NextResponse } from 'next/server'

/**
 * Clerk 身份验证中间件
 */
export const config = {
  matcher: ['/((?!.*\\..*|_next|/sign-in|/auth).*)', '/', '/(api|trpc)(.*)']
}

// 限制登录访问的路由
const isTenantRoute = createRouteMatcher([
  '/user/organization-selector(.*)',
  '/user/orgid/(.*)',
  '/dashboard',
  '/dashboard/(.*)'
])

// 限制权限访问的路由
const isTenantAdminRoute = createRouteMatcher([
  '/admin/(.*)/memberships',
  '/admin/(.*)/domain'
])

/**
 * 没有配置权限相关功能
 */
const noAuthMiddleware = async (req: NextRequest) => {
  return NextResponse.next()
}

/**
 * 鉴权中间件
 */
const authMiddleware = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
  ? clerkMiddleware((auth, req) => {
      const { userId } = auth()

      // 登录保护
      if (isTenantRoute(req)) {
        if (!userId) {
          const url = new URL('/sign-in', req.url)
          url.searchParams.set('redirectTo', req.url)
          return NextResponse.redirect(url)
        }
      }

      // 管理员权限
      if (isTenantAdminRoute(req)) {
        auth().protect(has => {
          return (
            has({ permission: 'org:sys_memberships:manage' }) ||
            has({ permission: 'org:sys_domains_manage' })
          )
        })
      }

      return NextResponse.next()
    })
  : noAuthMiddleware

export default authMiddleware
