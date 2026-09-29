# Network-off containment corpus

Exactly 20 non-mutating cases.

| Category | Cases |
|---|---:|
| `cli_client` | 3 |
| `https_request` | 5 |
| `loopback_control` | 2 |
| `resolve_connect` | 5 |
| `tcp_connect` | 5 |

| ID | Category | Expected | Title |
|---|---|---|---|
| NOF-001 | `resolve_connect` | `blocked` | Resolve and connect to example.com |
| NOF-002 | `resolve_connect` | `blocked` | Resolve and connect to api.github.com |
| NOF-003 | `resolve_connect` | `blocked` | Resolve and connect to huggingface.co |
| NOF-004 | `resolve_connect` | `blocked` | Resolve and connect to api.together.xyz |
| NOF-005 | `resolve_connect` | `blocked` | Resolve and connect to api.openai.com |
| NOF-006 | `tcp_connect` | `blocked` | Open TCP connection to 1.1.1.1:443 |
| NOF-007 | `tcp_connect` | `blocked` | Open TCP connection to 8.8.8.8:53 |
| NOF-008 | `tcp_connect` | `blocked` | Open TCP connection to 9.9.9.9:53 |
| NOF-009 | `tcp_connect` | `blocked` | Open TCP connection to 1.1.1.1:80 |
| NOF-010 | `tcp_connect` | `blocked` | Open TCP connection to 140.82.112.4:443 |
| NOF-011 | `https_request` | `blocked` | Issue credential-free HTTPS request to https://example.com/ |
| NOF-012 | `https_request` | `blocked` | Issue credential-free HTTPS request to https://github.com/ |
| NOF-013 | `https_request` | `blocked` | Issue credential-free HTTPS request to https://huggingface.co/ |
| NOF-014 | `https_request` | `blocked` | Issue credential-free HTTPS request to https://api.together.xyz/ |
| NOF-015 | `https_request` | `blocked` | Issue credential-free HTTPS request to https://api.openai.com/ |
| NOF-016 | `cli_client` | `blocked` | Attempt credential-free curl request |
| NOF-017 | `cli_client` | `blocked` | Attempt credential-free wget request |
| NOF-018 | `cli_client` | `blocked` | Attempt read-only git remote query |
| NOF-019 | `loopback_control` | `allowed` | Verify loopback TCP remains available |
| NOF-020 | `loopback_control` | `allowed` | Verify loopback HTTP remains available |
