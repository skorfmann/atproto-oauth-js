import { OAuthClient, type OAuthConfig } from 'atproto-oauth-js'

// Define the config type
export type ClientConfig = {
  clientId: string
  redirectUri: string
  clientUri: string
  jwksUri: string
  privateJwk: string
  publicJwk: string
  authStore: KVNamespace
}

// Create the OAuth config factory
export function createOAuthConfig(config: ClientConfig): OAuthConfig {
  return {
    clientMetadata: {
      client_id: config.clientId,
      dpop_bound_access_tokens: true,
      application_type: "web",
      subject_type: "public",
      grant_types: ["authorization_code", "refresh_token"] as const,
      response_types: ["code"] as const,
      scope: "atproto",
      client_name: "shipped.dev",
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      redirect_uris: [config.redirectUri],
      client_uri: config.clientUri,
      jwks_uri: config.jwksUri,
    },
    keys: {
      privateJwk: config.privateJwk,
      publicJwk: config.publicJwk,
    },
    storage: {
      async saveAuthRequest(data) {
        const key = `auth_request:${data.state}`
        await config.authStore.put(key, JSON.stringify(data), {
          expirationTtl: 600 // expire after 10 minutes
        })
      },

      async getAuthRequest(state) {
        const key = `auth_request:${state}`
        const data = await config.authStore.get(key)
        return data ? JSON.parse(data) : null
      },

      async deleteAuthRequest(state) {
        const key = `auth_request:${state}`
        await config.authStore.delete(key)
      },

      async saveSession(session) {
        const sessionId = generateSessionId();
        const sessionWithId = {
          ...session,
          sessionId
        };

        const sessionKey = `session:${sessionId}`;
        const didKey = `did_session:${session.did}`;

        await config.authStore.put(sessionKey, JSON.stringify(sessionWithId), {
          expirationTtl: 24 * 60 * 60
        });

        await config.authStore.put(didKey, sessionId, {
          expirationTtl: 24 * 60 * 60
        });

        return sessionId;
      },

      async getSession(id) {
        const key = `session:${id}`
        const data = await config.authStore.get(key)
        return data ? JSON.parse(data) : null
      },

      async getSessionByDid(did) {
        const didKey = `did_session:${did}`
        const sessionId = await config.authStore.get(didKey)

        if (!sessionId) return null

        return this.getSession(sessionId)
      },

      async deleteSession(id) {
        const key = `session:${id}`
        const sessionData = await config.authStore.get(key)

        if (sessionData) {
          const session = JSON.parse(sessionData)
          const didKey = `did_session:${session.did}`
          await Promise.all([
            config.authStore.delete(key),
            config.authStore.delete(didKey)
          ])
        }
      },
    }
  }
}

// Create and export the client factory
export function createClient(config: ClientConfig) {
  return new OAuthClient(createOAuthConfig(config))
}

function generateSessionId(): string {
  // Generate 32 random bytes and convert to base64url
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
