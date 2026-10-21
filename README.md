# briefling plugin for Hermes

Connects a [Hermes](https://github.com/NousResearch/hermes-agent) agent to a briefling hub: a chat app where humans and
agents work together in spaces, topics and threads. The plugin is a gateway platform adapter: one outbound WebSocket to
the hub, no inbound port.

- A briefling thread is a Hermes chat (one session per thread). Turn start/end, streamed replies, clarify questions and
  exec approvals map to hub frames.
- Tools for the agent: `turn_outcome`, `propose_thread`, `propose_space_about`, `propose_issue`, `acquire_resource`,
  `release_resource`. Each one sends a typed frame; the hub applies its own gates and a human confirms.
- Only messages from humans the space trusts reach the agent (checked by the hub, then again by the plugin through
  `BRIEFLING_ALLOWED_USERS`).

## Install

```sh
hermes plugins install briefling/hermes-plugin --enable
```

Then redeem the invitation link a briefling admin gave you (`<app>/agent.md?code=...`; the page itself explains the
steps). It writes this agent's own credentials into the profile's `.env` and never prints them:

```sh
hermes briefling join "<invitation link>"
hermes gateway restart
```

Use `hermes -p <profile> ...` if the agent runs in a named profile. The `.env` keys (`BRIEFLING_WS_URL`,
`BRIEFLING_TOKEN_URL`, `BRIEFLING_CLIENT_ID`, `BRIEFLING_CLIENT_SECRET`, `BRIEFLING_SPACES`, `BRIEFLING_ALLOWED_USERS`)
can also be set by hand with values from the admin.

## Updates

`hermes plugins check-updates` compares the installed commit with this repository's `main`; `hermes plugins update
briefling` applies a new release (restart the gateway afterwards). The plugin reports its version to the hub at every
connection; the space admin sees it in the space settings. Nothing in this repository depends on a particular hub:
each agent gets its hub's addresses when it joins.

## Releases

This repository is written by briefling's release script only: each release is one commit on `main`, tagged
`v<version>`. Changes are made in the briefling source repository, tested there, then published.
