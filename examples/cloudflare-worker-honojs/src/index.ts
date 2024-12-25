import { Hono } from 'hono'
import { createClient } from './client'
import type { OAuthClient } from 'atproto-oauth-js'
import { getSignedCookie, setSignedCookie } from 'hono/cookie'

type Bindings = {
  AUTH_STORE: KVNamespace
  OAUTH_CLIENT_ID: string
  OAUTH_REDIRECT_URI: string
  CLIENT_URI: string
  JWKS_URI: string
  PRIVATE_JWK: string
  PUBLIC_JWK: string
  COOKIE_SECRET: string
}

type Variables = {
  oauth: OAuthClient
  userHandle?: string
}

const app = new Hono<{
  Bindings: Bindings,
  Variables: Variables
}>()

app.use('*', async (c, next) => {
  const client = createClient({
    clientId: c.env.OAUTH_CLIENT_ID,
    redirectUri: c.env.OAUTH_REDIRECT_URI,
    clientUri: c.env.CLIENT_URI,
    jwksUri: c.env.JWKS_URI,
    privateJwk: c.env.PRIVATE_JWK,
    publicJwk: c.env.PUBLIC_JWK,
    authStore: c.env.AUTH_STORE,
  })
  c.set('oauth', client)
  await next()
})

app.use('*', async (c, next) => {
  console.log('sessionId', JSON.stringify(c.env))
  const sessionId = await getSignedCookie(c, c.env.COOKIE_SECRET, 'session')
  if (sessionId) {
    const oauth = c.get('oauth')
    try {
      const session = await oauth.getSession(sessionId)
      if (session?.username) {
        c.set('userHandle', session.username)
      }
    } catch (err) {
      console.error('Session validation failed:', err)
    }
  }
  await next()
})

app.get('/', (c) => {
  return c.text(`Hello ATProto OAuth: ${c.var.userHandle || 'anonymous'}`)
})

app.get('/auth/callback', async (c) => {
  const url = new URL(c.req.url)
  const params = new URLSearchParams(url.search)

  const oauth = c.get('oauth')
  const result = await oauth.handleCallback(params)

  await setSignedCookie(c, 'session', result.sessionId, c.env.COOKIE_SECRET, {
    httpOnly: true,
    secure: true,
    path: '/',
    sameSite: 'Lax',
    maxAge: 7 * 24 * 60 * 60 // 7 days
  })

  return c.redirect(c.env.CLIENT_URI)
})

// path matches the client metadata in the atproto-oauth-js client
app.get('/auth/client-metadata.json', (c) => {
  const oauth = c.get('oauth')
  return c.json(oauth.getClientMetadata())
})

// path matches the client metadata in the atproto-oauth-js client
app.get('/auth/jwk.json', async (c) => {
  const oauth = c.get('oauth')
  return c.json(await oauth.getJwks())
})

app.get('/auth/login', async (c) => {
  try {
    // Get handle from query parameter
    const handle = c.req.query('handle')
    if (!handle) {
      return c.json({ error: 'Missing handle parameter' }, 400)
    }

    const oauth = c.get('oauth')
    // this should be extracted from the given user handle
    const url = await oauth.initiateSignIn(handle, 'https://bsky.social');

    return c.redirect(url.redirectUrl)
  } catch (err) {
    return c.json({ error: String(err) }, 500)
  }
})

export default app
