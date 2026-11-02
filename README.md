# singgalang

One CLI for backend developers to manage their web service: **nginx sites**, **SSL certificates**, and **firewall ports** — including apps running in Docker. Ships with an **MCP server** so AI agents can drive the same operations.

## Why

Setting up a web service on a server means touching four different tools: nginx configs, certbot, ufw, and docker. singgalang wraps them behind one consistent CLI with dry-run support, confirmation prompts, and safe config validation — a broken config is never applied.

## Requirements

| Dependency | Needed for |
|---|---|
| nginx (host install **or** docker) | serving sites |
| certbot | SSL certificates (`ssl` commands) |
| ufw | firewall (`port` commands, auto-open 80/443) |
| docker | container discovery (`site add --container`), nginx-in-docker mode |

`sinnglang init` detects all of them and tells you what's missing.

## Install

```sh
go build -o singgalang .
sudo mv singgalang /usr/local/bin/
```

## Quick start

```sh
# 1. detect environment, create state (~/.singgalang)
singgalang init

# 2. add a site that reverse-proxies to a local app on port 3000
singgalang site add --domain api.example.com --proxy 3000

# ...or discover the port from a Docker container
singgalang site add --domain app.example.com --container myapp

# ...or serve static files
singgalang site add --domain www.example.com --root /srv/www

# 3. issue a Let's Encrypt certificate (opens 443 automatically)
singgalang ssl issue --domain api.example.com --email you@example.com

# 4. manage firewall ports directly
singgalang port open --port 8080
singgalang port list

# 5. validate + reload nginx after manual edits
singgalang reload
```

## Commands

```
singgalang init                       detect environment, set up state
singgalang site add                   --domain D (--proxy [host:]port | --root PATH | --container NAME)
singgalang site list                  [--domain D]
singgalang site remove                --domain D
singgalang site enable|disable        --domain D
singgalang ssl issue                  --domain D [--email E]
singgalang ssl list                   [--domain D]
singgalang ssl renew                  (with --dry: certbot --dry-run)
singgalang port open                  --port N [--tcp|--udp] [--from CIDR]
singgalang port close                 --port N
singgalang port list
singgalang reload                     nginx -t + reload
singgalang mcp                        run the MCP server over stdio (for AI agents)
```

Global flags:

- `--dry` — print the plan (and rendered config) without changing anything
- `--force` — skip confirmation prompts
- `--state-dir` — override the state directory (default `~/.singgalang`)

## How it stays safe

- **Plan → confirm → act.** Every mutating command prints what it will do first; `--dry` stops after the plan.
- **Validate before apply.** Configs are written, checked with `nginx -t`, and rolled back automatically if validation fails. Only then is nginx reloaded.
- **Privilege separation.** Commands that need root re-exec themselves via `sudo`, passing the state dir explicitly so the elevated process shares the same state.
- **Firewall ownership tracking.** singgalang records which ports *it* opened; `port close` refuses to touch rules it didn't create unless you pass `--force`, and `site remove` only closes ports when the last site goes away.
- **Honest port listing.** `port list` shows ufw rules and Docker-published ports separately, and warns that **Docker-published ports on 0.0.0.0 bypass ufw entirely** (ufw cannot filter them). Prefer `-p 127.0.0.1:3000:3000` for app ports.

## MCP server (AI agents)

`singgalang mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio, exposing the same operations the CLI uses — both are thin wrappers over one shared core (`internal/ops`), so behaviour is identical.

Configure your AI client (Claude Code, OpenCode, etc.):

```json
{
  "mcpServers": {
    "singgalang": { "command": "singgalang", "args": ["mcp"] }
  }
}
```

Tools exposed:

| Tool | Purpose |
|---|---|
| `detect_environment` | OS, nginx/docker/certbot/ufw presence, mode, root status |
| `init` | detect environment and write state |
| `site_add` / `site_list` / `site_remove` / `site_set_enabled` | manage sites |
| `ssl_issue` / `ssl_list` / `ssl_renew` | manage certificates |
| `port_open` / `port_close` / `port_list` | manage firewall ports |
| `reload` | validate + reload nginx |

Design notes for agents:

- **Structured output.** Every tool returns JSON (`structuredContent`) — plans, warnings, and rendered configs — not prose.
- **`dry_run` on mutating tools.** `site_add`, `site_remove`, `site_set_enabled`, `ssl_issue`, `ssl_renew`, `port_open` and `port_close` accept `dry_run: true` to preview without changing anything.
- **Safety annotations.** Tools are tagged read-only / additive / destructive so clients can gate destructive calls.
- **Errors are tool errors, not crashes.** Invalid input or failed validation surfaces as `isError` with an actionable message (e.g. an ambiguous container lists the candidate ports to choose from).
- **Concurrency-safe.** Mutating operations are serialized under a lock, so parallel agent calls can't interleave state read/modify/write.
- **Privileges.** The MCP server does not re-exec via `sudo` (there's no TTY). Operations needing root return an error telling the operator to run it with privileges; launch the client or server accordingly.

## Nginx modes

**Host mode** (default when nginx is installed): configs go to `/etc/nginx/sites-available` (or `conf.d`), managed as `singgalang-<domain>.conf`.

**Docker mode** (`singgalang init --nginx-mode docker`): singgalang generates a managed directory `~/.singgalang/nginx/` containing `nginx.conf`, `sites-enabled/`, and a `docker-compose.yaml`. Start it with:

```sh
cd ~/.singgalang/nginx && docker compose up -d
```

The compose file mounts `sites-enabled`, the ACME webroot (`/var/www/certbot`), and certs (`/etc/letsencrypt`). Certbot still runs on the host, so renewal is a plain `singgalang ssl renew`.

## Notes & limitations

- SSL uses **certbot in webroot mode** — singgalang owns the nginx config (certbot never rewrites server blocks); every generated config includes the `/.well-known/acme-challenge/` location.
- App ports are proxied over `127.0.0.1`, so they survive container restarts and stay off the public interface.
- WebSocket `Upgrade` headers are not generated yet (needs an http-context `map`); add them manually if needed.
- v1 targets Debian/Ubuntu-style layouts (systemctl + ufw); other distros may work but aren't tested.

## Development

```sh
go build ./...   # compile
go vet ./...     # static checks
go test ./...    # unit tests (rendering, ufw parsing, state, docker inspect, ops)
```

Project layout:

```
cmd/              cobra CLI (thin interactive layer: plan/confirm/sudo)
internal/ops/     shared operations core — used by both CLI and MCP
internal/mcp/     MCP server: wires ops to tools over stdio
internal/nginx/   template rendering, host/docker managers, validation
internal/firewall/  ufw wrapper
internal/ssl/     certbot wrapper, certificate parsing
internal/docker/  docker inspect/discovery
internal/state/   manifest persistence
internal/system/  shell-out, root detection, OS detection
templates/        embedded nginx/compose templates
```
