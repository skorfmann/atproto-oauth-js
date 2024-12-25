// types.ts
export interface OAuthConfig {
  clientMetadata: {
    client_id: string;
    dpop_bound_access_tokens: true;
    application_type: "web";
    subject_type: "public";
    grant_types: readonly ["authorization_code", "refresh_token"];
    response_types: readonly ["code"];
    scope: "atproto";
    client_name: string;
    token_endpoint_auth_method: "private_key_jwt";
    token_endpoint_auth_signing_alg: "ES256";
    redirect_uris: readonly string[];
    client_uri: string;
    jwks_uri: string;
  },
  keys: {
    privateJwk: string;
    publicJwk: string;
  };
  storage: {
    saveAuthRequest: (data: AuthRequest) => Promise<void>;
    getAuthRequest: (state: string) => Promise<AuthRequest | null>;
    deleteAuthRequest: (state: string) => Promise<void>;
    saveSession: (session: OAuthSession) => Promise<string>;
    getSession: (id: string) => Promise<OAuthSession | null>;
    getSessionByDid: (did: string) => Promise<OAuthSession | null>;
    deleteSession: (id: string) => Promise<void>;
  };
}

export interface AuthRequest {
  did: string;
  iss: string;
  username: string;
  nonce: string;
  state: string;
  pkceVerifier: string;
  dpopPrivateJwk: string;
  dpopPublicJwk: string;
  expiresAt: Date;
  createdAt: Date;
}

export interface OAuthSession {
  sessionId: string;
  did: string;
  username: string;
  iss: string;
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
  createdAt: Date;
  dpopNonce: string;
  dpopPrivateJwk: string;
  dpopPublicJwk: string;
}

// Additional types
export interface DPoPKeys {
  privateDpopKey: CryptoKey;
  publicDpopKey: CryptoKey;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  dpop_nonce?: string;
  sub?: string;
}

// oauth-client.ts
import {
  calculatePKCECodeChallenge,
  discoveryRequest,
  generateKeyPair,
  generateRandomCodeVerifier,
  generateRandomState,
  processDiscoveryResponse,
  pushedAuthorizationRequest,
  authorizationCodeGrantRequest,
  validateAuthResponse,
  protectedResourceRequest,
  revocationRequest,
  isOAuth2Error,
} from "oauth4webapi";
import {
  exportJWK,
  importJWK,
  SignJWT,
  jwtVerify,
  calculateJwkThumbprint,
} from "jose";
import { getDidFromHandleOrDid, isDid } from "./identity";

// First, add a type for the token response near the top with other interfaces
interface TokenResponseJson {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
}

export class OAuthClient {
  constructor(private config: OAuthConfig) {
    if (!config.clientMetadata.redirect_uris.length) {
      throw new Error("At least one redirect URI must be configured");
    }
  }

  private async validateHandle(identifier: string): Promise<{did: string, username: string}> {
    if (isDid(identifier)) {
      return {
        did: identifier,
        username: identifier
      };
    }

    const did = await getDidFromHandleOrDid(identifier);
    if (!did) {
      throw new Error("Invalid handle or DID");
    }

    return {
      did,
      username: identifier
    };
  }

  async initiateSignIn(identifier: string, authServerUrl: string) {
    this.log('=== Starting Sign In Process ===');
    this.log('Input parameters:', { identifier, authServerUrl });

    // Handle validation
    this.log('Validating identifier...');
    const {did, username} = await this.validateHandle(identifier);
    this.log('Identifier validated:', { did, username });

    // Generate security parameters
    this.log('Generating security parameters...');
    const state = generateRandomState();
    const pkceVerifier = generateRandomCodeVerifier();
    this.log('Security parameters generated:', {
      stateLength: state.length,
      pkceVerifierLength: pkceVerifier.length
    });

    // Generate DPoP key pair
    this.log('Generating DPoP key pair...');
    const dpopKeyPair = await generateKeyPair("RS256", { extractable: true });
    this.log('DPoP key pair generated:', {
      hasPrivateKey: !!dpopKeyPair.privateKey,
      hasPublicKey: !!dpopKeyPair.publicKey
    });

    // Discover auth server
    this.log('Discovering auth server...', { url: authServerUrl });
    const discoveryResponse = await discoveryRequest(new URL(authServerUrl), { algorithm: "oauth2" });
    this.log('Discovery response received:', {
      status: discoveryResponse.status,
      headers: Object.fromEntries(discoveryResponse.headers)
    });

    const authServer = await processDiscoveryResponse(
      new URL(authServerUrl),
      discoveryResponse
    );
    this.log('Auth server metadata processed:', {
      issuer: authServer.issuer,
      endpoints: {
        authorization: authServer.authorization_endpoint,
        token: authServer.token_endpoint,
        par: authServer.pushed_authorization_request_endpoint
      }
    });

    // Make PAR request
    this.log('Initiating Pushed Authorization Request...');
    const parResponse = await this.makePARRequest({
      authServer,
      state,
      pkceVerifier,
      dpopKeyPair,
      identifier,
    });

    this.log('PAR response received:', {
      status: parResponse.status,
      headers: Object.fromEntries(parResponse.headers),
      ok: parResponse.ok
    });

    if (!parResponse.ok) {
      const errorText = await parResponse.text();
      this.log('PAR request failed:', { error: errorText });
      throw new Error(`Failed to push authorization request: ${errorText}`);
    }

    const dpopNonce = parResponse.headers.get("DPoP-Nonce");
    if (!dpopNonce) {
      this.log('Error: Missing DPoP nonce in response headers');
      throw new Error("Missing DPoP nonce");
    }
    this.log('DPoP nonce received:', { dpopNonce });

    const parData = await parResponse.json();
    this.log('PAR data received:', {
      requestUri: parData.request_uri,
      expiresIn: parData.expires_in
    });

    // Save auth request
    this.log('Saving auth request to storage...');
    let authRequest: AuthRequest;
    try {
    authRequest = {
      did,
      username,
      iss: authServer.issuer,
      nonce: dpopNonce,
      state,
      pkceVerifier,
      dpopPrivateJwk: JSON.stringify(
        await crypto.subtle.exportKey("jwk", dpopKeyPair.privateKey)
      ),
      dpopPublicJwk: JSON.stringify(
        await crypto.subtle.exportKey("jwk", dpopKeyPair.publicKey)
      ),
      expiresAt: new Date(Date.now() + 1000 * 60),
      createdAt: new Date(),
    };

    await this.config.storage.saveAuthRequest(authRequest);
    } catch (error) {
      this.log('Error saving auth request:', error);
      throw error;
    }
    this.log('Auth request saved successfully');

    let redirectUrl: string;

    try {
      redirectUrl = this.buildAuthorizationUrl(authServer, parData);
    } catch (error) {
      this.log('Error building authorization URL:', error);
      throw error;
    }
    this.log('=== Sign In Process Completed ===', {
      redirectUrl,
      state,
      expiresAt: authRequest.expiresAt
    });

    return {
      redirectUrl,
      state,
    };
  }

  async handleCallback(params: URLSearchParams) {
    this.log('Handling OAuth callback');
    const state = params.get("state");
    const code = params.get("code");
    const iss = params.get("iss");

    if (!state || !code || !iss) {
      this.log('Missing required parameters:', { state, code, iss });
      throw new Error("Missing required callback parameters");
    }

    const authRequest = await this.config.storage.getAuthRequest(state);
    if (!authRequest) {
      throw new Error("Invalid state");
    }

    // Verify issuer matches
    if (authRequest.iss !== iss) {
      throw new Error("Issuer mismatch");
    }

    // Get the auth server metadata
    const authServer = await this.getAuthServer(authRequest.iss);

    // Validate the authorization response
    const validationResult = await validateAuthResponse(
      authServer,
      { client_id: this.config.clientMetadata.client_id },
      params,
      state
    );

    if (isOAuth2Error(validationResult)) {
      throw new Error(`Invalid authorization response: ${validationResult.error_description || validationResult.error}`);
    }

    // Continue with the rest of the callback handling...
    const currentDid = await getDidFromHandleOrDid(authRequest.username);
    if (currentDid !== authRequest.did) {
      throw new Error("Handle/DID mismatch");
    }

    // Process callback and exchange code for tokens
    const tokens = await this.exchangeCodeForTokens(authServer, validationResult, authRequest);

    // Verify subject matches expected DID
    if (tokens.sub !== authRequest.did) {
      throw new Error("Token subject does not match expected DID");
    }

    console.log({tokens})

    // Create session
    const sessionId = await this.config.storage.saveSession({
      did: authRequest.did,
      username: authRequest.username,
      iss: authRequest.iss,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token!,
      expiresAt: new Date(Date.now() + (tokens.expires_in || 3600) * 1000),
      createdAt: new Date(),
      dpopNonce: tokens.dpop_nonce!,
      dpopPrivateJwk: authRequest.dpopPrivateJwk,
      dpopPublicJwk: authRequest.dpopPublicJwk,
      sessionId: '', // Will be set by storage implementation
    });

    // Clean up auth request
    await this.config.storage.deleteAuthRequest(state);

    this.log('Session created with ID:', sessionId);
    return { sessionId };
  }

  async makeAuthenticatedRequest(
    sessionId: string,
    input: RequestInfo,
    init?: RequestInit
  ) {
    this.log('Making authenticated request', { sessionId, url: input.toString() });

    const session = await this.config.storage.getSession(sessionId);
    if (!session) {
      throw new Error("Invalid session");
    }

    const { privateDpopKey, publicDpopKey } = await this.importDpopKeys(session);

    const makeRequest = (dpopNonce: string) => {
      const request = new Request(input, init);
      return protectedResourceRequest(
        session.accessToken,
        request.method,
        new URL(request.url),
        request.headers,
        request.body,
        {
          DPoP: {
            privateKey: privateDpopKey,
            publicKey: publicDpopKey,
            nonce: dpopNonce,
          },
        }
      );
    };

    let response = await makeRequest(session.dpopNonce);

    // Handle nonce refresh
    if (response.status === 401) {
      this.log('Received 401, attempting nonce refresh');
      const newNonce = response.headers.get("DPoP-Nonce");
      if (newNonce) {
        this.log('New DPoP nonce received');
        await this.config.storage.saveSession({
          ...session,
          dpopNonce: newNonce,
        });
        response = await makeRequest(newNonce);
      }
    }

    this.log('Request completed with status:', response.status);
    return response;
  }

  async revokeSession(sessionId: string) {
    this.log('Revoking session:', sessionId);

    const session = await this.config.storage.getSession(sessionId);
    if (!session) {
      throw new Error("Invalid session");
    }

    const authServer = await this.getAuthServer(session.iss);

    await revocationRequest(
      authServer,
      { client_id: this.config.clientMetadata.client_id },
      session.accessToken,
      {
        clientPrivateKey: await this.getClientPrivateKey(),
      }
    );

    await this.config.storage.deleteSession(sessionId);

    this.log('Session revoked successfully');
  }

  private async makePARRequest({
    authServer,
    state,
    pkceVerifier,
    dpopKeyPair,
    identifier,
  }: {
    authServer: any;
    state: string;
    pkceVerifier: string;
    dpopKeyPair: CryptoKeyPair;
    identifier: string;
  }) {
    this.log('Client configuration:', {
      auth_method: this.config.clientMetadata.token_endpoint_auth_method,
      auth_signing_alg: this.config.clientMetadata.token_endpoint_auth_signing_alg
    });

    const makeRequest = async (dpopNonce?: string) => {
      this.log('Making PAR request with params:', {
        hasNonce: !!dpopNonce,
        state,
        identifier
      });

      try {
        const clientPrivateKey = await this.getClientPrivateKey();
        this.log('Client private key obtained:', {
          hasKey: !!clientPrivateKey.key,
          hasKid: !!clientPrivateKey.kid
        });

        const challenge = await calculatePKCECodeChallenge(pkceVerifier);
        this.log('PKCE challenge calculated');

        const response = await pushedAuthorizationRequest(
          authServer,
          {
            client_id: this.config.clientMetadata.client_id,
            token_endpoint_auth_method: "private_key_jwt"
          },
          {
            response_type: "code",
            code_challenge: challenge,
            code_challenge_method: "S256",
            client_id: this.config.clientMetadata.client_id,
            state,
            redirect_uri: this.config.clientMetadata.redirect_uris[0]!,
            scope: this.config.clientMetadata.scope,
            login_hint: identifier,
          },
          {
            DPoP: dpopNonce ? {
              privateKey: dpopKeyPair.privateKey,
              publicKey: dpopKeyPair.publicKey,
              nonce: dpopNonce,
            } : undefined,
            clientPrivateKey,
          }
        );
        this.log('PAR request completed');
        return response;
      } catch (error) {
        this.log('PAR request failed:', error);
        throw error;
      }
    };

    // Try initial request without nonce
    this.log('Attempting initial PAR request without nonce');
    let response = await makeRequest();

    // Handle nonce retry if needed
    if (!response.ok) {
      const dpopNonce = response.headers.get("DPoP-Nonce");
      if (dpopNonce) {
        this.log('Retrying PAR request with new nonce');
        response = await makeRequest(dpopNonce);
      }
    }

    return response;
  }

  private async exchangeCodeForTokens(
    authServer: any,
    params: URLSearchParams,
    authRequest: AuthRequest
  ): Promise<TokenResponse> {
    const { privateDpopKey, publicDpopKey } = await this.importDpopKeys(authRequest);

    const response = await authorizationCodeGrantRequest(
      authServer,
      { client_id: this.config.clientMetadata.client_id,
        token_endpoint_auth_method: "private_key_jwt"
      },
      params,
      this.config.clientMetadata.redirect_uris[0]!,
      authRequest.pkceVerifier,
      {
        clientPrivateKey: await this.getClientPrivateKey(),
        DPoP: {
          privateKey: privateDpopKey,
          publicKey: publicDpopKey,
          nonce: authRequest.nonce,
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Token exchange failed: ${await response.text()}`);
    }

    const tokens = await response.json() as TokenResponseJson;
    return {
      ...tokens,
      dpop_nonce: response.headers.get("DPoP-Nonce") || undefined,
    };
  }

  private async getAuthServer(issuer: string) {
    return processDiscoveryResponse(
      new URL(issuer),
      await discoveryRequest(new URL(issuer), { algorithm: "oauth2" })
    );
  }

  private async importDpopKeys(
    session: Pick<OAuthSession, "dpopPrivateJwk" | "dpopPublicJwk">
  ): Promise<DPoPKeys> {
    const [privateDpopKey, publicDpopKey] = await Promise.all([
      crypto.subtle.importKey(
        "jwk",
        JSON.parse(session.dpopPrivateJwk),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        true,
        ["sign"]
      ),
      crypto.subtle.importKey(
        "jwk",
        JSON.parse(session.dpopPublicJwk),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        true,
        ["verify"]
      ),
    ]);

    return { privateDpopKey, publicDpopKey };
  }

  private async getClientPrivateKey() {
    const importedKey = await importJWK(JSON.parse(this.config.keys.privateJwk), "ES256");
    const jwk = await exportJWK(importedKey);
    const kid = await calculateJwkThumbprint(jwk);
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"],
    );

    return { key, kid };
  }


  private buildAuthorizationUrl(authServer: any, parData: any): string {
    const url = new URL(authServer.authorization_endpoint);
    url.searchParams.set("request_uri", parData.request_uri);
    url.searchParams.set("client_id", this.config.clientMetadata.client_id);
    return url.toString();
  }

  async restoreSession(did: string): Promise<OAuthSession | null> {
    const session = await this.config.storage.getSessionByDid(did);

    if (!session) {
      return null;
    }

    // Check if session needs refresh
    if (this.needsRefresh(session)) {
      return this.refreshSession(session);
    }

    return session;
  }

  private needsRefresh(session: OAuthSession): boolean {
    // Refresh when less than 5 minutes remaining
    const refreshBuffer = 5 * 60 * 1000;
    return Date.now() + refreshBuffer >= session.expiresAt.getTime();
  }

  private async refreshSession(session: OAuthSession): Promise<OAuthSession> {
    this.log('Refreshing session for DID:', session.did);

    const authServer = await this.getAuthServer(session.iss);

    const { privateDpopKey, publicDpopKey } = await this.importDpopKeys(session);

    const response = await authorizationCodeGrantRequest(
      authServer,
      { client_id: this.config.clientMetadata.client_id },
      new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: session.refreshToken,
      }),
      this.config.clientMetadata.redirect_uris[0]!,
      '',
      {
        clientPrivateKey: await this.getClientPrivateKey(),
        DPoP: {
          privateKey: privateDpopKey,
          publicKey: publicDpopKey,
          nonce: session.dpopNonce,
        },
      }
    );

    if (!response.ok) {
      this.log('Token refresh failed:', response.status);
      throw new Error(`Token refresh failed: ${await response.text()}`);
    }

    this.log('Session refreshed successfully');
    const tokens = await response.json() as TokenResponseJson;

    const updatedSession: OAuthSession = {
      ...session,
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || session.refreshToken,
      expiresAt: new Date(Date.now() + (tokens.expires_in || 3600) * 1000),
      dpopNonce: response.headers.get("DPoP-Nonce") || session.dpopNonce,
    };

    await this.config.storage.saveSession(updatedSession);

    return updatedSession;
  }

  public getClientMetadata(): OAuthConfig['clientMetadata'] {
    return this.config.clientMetadata;
  }

  public async getJwks() {
    const importedKey = await importJWK(JSON.parse(this.config.keys.privateJwk), "ES256");
    const jwk = await exportJWK(importedKey);
    const kid = await calculateJwkThumbprint(jwk);

    return {
      keys: [{
        kty: jwk.kty,
        x: jwk.x,
        y: jwk.y,
        crv: jwk.crv,
        kid,
      }]
    };
  }

  public async getSession(sessionId: string) {
    return this.config.storage.getSession(sessionId);
  }

  private log(message: string, ...args: any[]) {
    console.debug(`[OAuthClient] ${message}`, ...args);
  }
}
