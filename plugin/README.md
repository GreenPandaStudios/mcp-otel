# Connect the custom plugin

1. Open ChatGPT → Plugins → Add → **Add custom MCP server**.
2. Name it **MCP-OTel** and enter `https://otel.august.services/mcp` (replace the origin for another installation).
3. Choose OAuth with the installation's provided client ID and client secret. The server publishes discovery metadata. Its token endpoint uses `client_secret_basic`, authorization-code flow and S256 PKCE.
4. The default registered callback is `https://chatgpt.com/connector_platform_oauth_redirect`. If the management page supplies a different callback, an administrator must add that exact URI to this client's allowlist. Do not use a wildcard.
5. Complete **Connect this installation** in the browser. There is no separate Sign in with ChatGPT integration and no second factor. The confidential connection authorizes this installation; a random ChatGPT account has no credentials.
6. Create it as a plugin and verify that the ten tools and three event definitions are discovered. Rescan after server tool/event changes.

The `plugin.json` and `mcp.json` files form a portable package. Replace the client ID placeholder for a private installation; keep secrets out of the archive. A registered `plugin_asdk_app...` mapping may also be used after creating the remote connection. Public source distribution does not publish the custom connection or its credentials.

## Subscribe in the supported surface

Use a Work cloud chat or dot. For example, adapt this to your own investigation preferences:

> Subscribe to MCP-OTel incident.changed for namespace mcp-otel-synthetic and service repair-demo. When an event arrives, inspect the included logs and use the query tools to investigate. Show evidence and uncertainty. Do not deploy a repair without my explicit approval of its exact tested version.

The user controls ongoing investigation instructions. The server sends events directly to the callback supplied by ChatGPT; it does not start a separate LLM loop.

Confirm actual event receipt in that chat, then stop monitoring and verify unsubscription. A callback acknowledgement alone does not prove ChatGPT processed the event. See the [official supported surfaces](https://developers.openai.com/plugins/build/mcp-events); eligibility and workspace controls must be verified for your account.

## Repair approval

`repair_status` renders the status/checks widget. Its review button opens the authenticated MCP-OTel review panel using the browser session established during connection. The panel shows the diff, PR, checks, image digest, target and exact version. Approval requires a deliberate button press there; model tool arguments cannot approve. This hosted review panel must be exercised in the actual ChatGPT connection before calling the intended plugin approval experience verified.

If the review uses a different browser profile and has no connection cookie, reconnect the plugin in that profile. Do not weaken cookie or CSRF checks as a workaround.
