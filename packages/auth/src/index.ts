import { expo } from '@better-auth/expo'
import { db } from '@keywarden/db'
import * as schema from '@keywarden/db/schema/auth'
import { env } from '@keywarden/env/api'
import { betterAuth } from 'better-auth'
import { drizzleAdapter } from 'better-auth/adapters/drizzle'
import { siws } from 'better-auth-solana'

export const auth = betterAuth({
  database: drizzleAdapter(db, {
    provider: 'sqlite',

    schema: schema,
  }),
  trustedOrigins: [
    ...env.CORS_ORIGINS,
    ...(env.NODE_ENV === 'development'
      ? [
          'exp://',
          'exp://**',
          'keywarden://**',
          'exp://192.168.*.*:*/**',
          'http://localhost:8081',
        ]
      : []),
  ],
  emailAndPassword: {
    enabled: true,
  },
  advanced: {
    defaultCookieAttributes: {
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    },
  },
  plugins: [
    expo(),
    siws({
      anonymous: true,
      domain: new URL(env.BETTER_AUTH_URL).hostname,
      emailDomainName: env.SOLANA_EMAIL_DOMAIN,
    }),
  ],
})
