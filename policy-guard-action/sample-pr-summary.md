### Isonapse policy review: `.isonapse/policy.lua`

| Effect | Area | Change |
| --- | --- | --- |
| 🔓 widening | actions | `tool:Bash:curl`: DEFER -> PERMIT |
| 🔓 widening | allowed_domains | `cap:http-request` may now reach `collector.attacker.example` |
| 🔓 widening | allowed_domains | `tool:WebFetch` may now reach `collector.attacker.example` |
| 🔓 widening | blocked_capabilities | blocked capability removed for `*`: `tool:Bash:nc` |
| 🔓 widening | max_payload_size | `cap:http-request`: 65536 -> 10485760 |
| 👀 needs review | check_action | runtime `check_action` source changed (cannot be diffed semantically) |
| ℹ️ no effect | allowed_domains | `webhook.site` added to the `cap:http-request` allowlist but still blocked by `blocked_domains` (no effect; likely a mistake) |
| ℹ️ no effect | allowed_domains | `webhook.site` added to the `tool:WebFetch` allowlist but still blocked by `blocked_domains` (no effect; likely a mistake) |

**6** change(s) give agents more power; **0** restrict them.
