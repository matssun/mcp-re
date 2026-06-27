# MCP-S Intro Voiceover Timing

The voiceover is the timing master for the rough animatic. The scene file should be adjusted to these sections when the recorded/generated voiceover duration changes.

| Time | Scene | Voiceover |
| --- | --- | --- |
| 0:00-0:10 | MCP intro | MCP gives agents a standard way to connect to tools: source control, databases, internal docs, calendars, payment APIs, and the systems developers already use. |
| 0:10-0:22 | Less glue | That is why developers like it. Instead of one-off glue for every tool and every host, MCP gives us reusable integrations with a common shape: host, client, server, tool. |
| 0:22-0:38 | Security boundary | But that call path is also a boundary. Once an agent asks a tool to do something sensitive, we need evidence about identity, integrity, freshness, replay, and response binding. |
| 0:38-0:55 | Concrete risk | Take a payment request. The agent sends: pay invoice one zero four two. If that call can be copied, replayed, or changed, one trusted action can become two bad ones. |
| 0:55-1:14 | Enter MCP-S | MCP-S adds verifiable runtime evidence around those MCP calls. A request can carry a signature, a nonce, an expiry, authorization context, and a request hash. The response can be bound back with its own hash. The point is not magic security. The point is evidence that a verifier can check while the system is running. |
| 1:14-1:25 | KMS | For enterprise deployments, signing keys can stay in Google Cloud KMS. MCP-S asks KMS to sign. The private key is not exported. MCP-S receives signatures, not raw key material. |
| 1:25-1:30 | Payoff | The payoff is operational and testable: valid requests are accepted, tampered requests are rejected, replays are rejected, and bad response bindings are rejected. Try MCP-S at github dot com slash matssun slash mcps. |

## TTS Direction

Speak in a calm, technical, confident tone. Use neutral international English. Keep a steady pace with short pauses between ideas. Do not sound dramatic or salesy.
