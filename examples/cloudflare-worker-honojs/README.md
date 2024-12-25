# Cloudflare Worker HonoJS Example for ATProto OAuth

This is an example of how to use the `atproto-oauth-js` library in a Cloudflare Worker with HonoJS.

**Note:** This is a work in progress and hasn't been tested in production. Use with caution.

## Setup

### 1. Install Dependencies
```bash
pnpm install
```

### 2. Environment Setup
Create a `.dev.vars` file from the example:
```bash
cp .dev.vars.example .dev.vars
```

### 3. Generate Required Keys and Secrets

#### Cookie Secret
Generate a secure cookie secret:
```bash
openssl rand -base64 32
```

#### JWT Keys
Generate the private and public key pair:
```bash
pnpm run generate
```

### 4. Configure Cloudflare Tunnel

1. Install and set up [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-local-tunnel/)
2. Start the tunnel:
```bash
pnpm run dev:tunnel
```
3. Copy the tunnel URL and update your `.dev.vars` file with the following values:
```
OAUTH_CLIENT_ID='https://your-tunnel-url/auth/client-metadata.json'
OAUTH_REDIRECT_URI='https://your-tunnel-url/auth/callback'
CLIENT_URI='https://your-tunnel-url'
JWKS_URI='https://your-tunnel-url/auth/jwk.json'
PRIVATE_JWK=<from generate command>
PUBLIC_JWK=<from generate command>
COOKIE_SECRET=<from openssl command>
```

### 5. Development
Start the development server:
```bash
pnpm run dev
```

## API Endpoints

- `GET /` - Home page showing user handle or "anonymous"
- `GET /auth/login?handle={userHandle}` - Initiates sign-in flow
- `GET /auth/callback` - OAuth callback handler
- `GET /auth/client-metadata.json` - OAuth client metadata
- `GET /auth/jwk.json` - JWK endpoint

## Storage

The example uses Cloudflare KV for storing:
- Authentication requests (10-minute TTL)
- User sessions (24-hour TTL)

## Production Deployment

**Warning:** This example is not recommended for production use without a thorough security audit.