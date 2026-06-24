import { db } from '@keywarden/db'
import { user } from '@keywarden/db/schema/auth'
import type { RouterClient } from '@orpc/server'
import { eq } from 'drizzle-orm'

import { authPublicProcedure } from '../index'
import { solanaRouter } from './solana'
import { todoRouter } from './todo'

export const appRouter = {
  healthCheck: authPublicProcedure.handler(() => {
    return 'OK'
  }),
  me: authPublicProcedure.handler(async ({ context }) => {
    if (!context.session?.user?.id) {
      return null
    }

    const [currentUser] = await db
      .select({
        email: user.email,
        id: user.id,
        image: user.image,
        name: user.name,
      })
      .from(user)
      .where(eq(user.id, context.session.user.id))
      .limit(1)

    return currentUser ?? null
  }),
  solana: solanaRouter,
  todo: todoRouter,
}
export type AppRouter = typeof appRouter
export type AppRouterClient = RouterClient<typeof appRouter>
