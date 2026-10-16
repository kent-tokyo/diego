# Web and WordPress evidence contract

The `web` and `wordpress` modules require explicit authorised targets and use
unauthenticated requests. An outcome describes what the sampled response
established; it is separate from the finding's severity and confidence.

| Outcome | Meaning |
|---|---|
| `confirmed` | A directly observable property of the sampled Web response, such as a missing header or an HTTP to HTTPS redirect. This does not establish application security. |
| `exposed` | A public WordPress URL, version marker, or pingback header was observed. This does not establish exploitability. |
| `inconclusive` | The response cannot support the proposed posture conclusion, for example an unfollowed redirect, error page, or HEAD 405. |
| `unavailable` | Input validation or transport failed before a usable response was obtained. |

Only these two modules currently set `outcome`; it is optional in the report
schema so old reports remain readable. JSON serialises it on each finding and
Markdown prints it beside the module name. `evidence.request_count` counts
attempted HTTP requests for the explicit target, including a Web HEAD fallback
or WordPress's three fixed endpoint requests. `failure_reason` groups transport
failures without treating them as header or WordPress defects.

`observed_header_names` lists selected header **names**. Cookie values and
response bodies are never written to findings. The WordPress root requests
`Range: bytes=0-65535` and analyses at most 64 KiB of body; a server can
ignore Range, so this is an application read limit, not a guaranteed network
transfer limit. No redirect destination is contacted.

Loopback fixtures in `tests/web_posture_e2e.rs` check methods, counts, redirect
handling, fallback, malformed replies, timeout, and the body prefix. They do
not measure real-site accuracy or domain-scale performance.
