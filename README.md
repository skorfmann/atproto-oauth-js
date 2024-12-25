# ATProto OAuth JS

This is a library for handling ATProto OAuth flows, particularly targeting Cloudflare Workers and similar non node.js environments. If you're using node.js, you should use the [@atproto/oauth-client-node](https://www.npmjs.com/package/@atproto/oauth-client-node) library instead.

It's a work in progress and may not work as expected. It hasn't been tested in production yet. It's likely to change. And probably it's not a secure example nor a secure implementation.

## Examples

- [Cloudflare Worker HonoJS](examples/cloudflare-worker-honojs/)

## Library

- [atproto-oauth-js](packages/atproto-oauth-js/)

## Credits

This was mainly extracted from the [frontpage.fyi](https://github.com/likeandscribe/frontpage/blob/5d362ae011b4ca83b15a30434468ac7b8b667497/packages/frontpage/lib/auth.ts) codebase.

Fruther inspiration can be found in https://github.com/pilcrowonpaper/atproto-oauth-example/

