# Metasploit MCP Server

An MCP (Model Context Protocol) server that provides Claude Code with access to the Metasploit Framework RPC API. This enables AI-assisted penetration testing workflows for **authorized security testing only**.

## Prerequisites

1. **Metasploit Framework** installed and running
2. **Node.js** 18+
3. **Metasploit RPC service** enabled

## Starting Metasploit RPC

### Option 1: Using msfrpcd (recommended)

```bash
msfrpcd -U msf -P yourpassword -S -f
```

Options:
- `-U` - Username
- `-P` - Password
- `-S` - Enable SSL
- `-f` - Run in foreground

### Option 2: From msfconsole

```bash
msfconsole
msf6 > load msgrpc ServerHost=0.0.0.0 ServerPort=55552 User=msf Pass=yourpassword SSL=true
```

## Installation

```bash
cd /path/to/msftool
npm install
npm run build
```

## Configuration

Set environment variables before running:

| Variable | Default | Description |
|----------|---------|-------------|
| `MSF_HOST` | `127.0.0.1` | Metasploit RPC host |
| `MSF_PORT` | `55552` | Metasploit RPC port |
| `MSF_SSL` | `true` | Use SSL (`true`/`false`) |
| `MSF_USERNAME` | `msf` | RPC username |
| `MSF_PASSWORD` | (required) | RPC password |
| `MSF_TOKEN` | (optional) | Pre-generated auth token |

## Claude Code Integration

Add to your Claude Code MCP settings (`~/.claude/settings.json` or project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "metasploit": {
      "command": "node",
      "args": ["/path/to/msftool/dist/index.js"],
      "env": {
        "MSF_HOST": "127.0.0.1",
        "MSF_PORT": "55552",
        "MSF_SSL": "true",
        "MSF_USERNAME": "msf",
        "MSF_PASSWORD": "yourpassword"
      }
    }
  }
}
```

## Available Tools

### Connection & Status

| Tool | Description |
|------|-------------|
| `msf_connect` | Authenticate to Metasploit RPC |
| `msf_version` | Get Metasploit version info |
| `msf_status` | Get status including module stats and DB |

### Module Operations

| Tool | Description |
|------|-------------|
| `msf_module_search` | Search for modules by keyword |
| `msf_module_info` | Get module details |
| `msf_module_options` | Get module options |
| `msf_module_execute` | Execute a module |
| `msf_module_check` | Run vulnerability check |
| `msf_compatible_payloads` | List compatible payloads |

### Session Management

| Tool | Description |
|------|-------------|
| `msf_sessions_list` | List active sessions |
| `msf_session_interact` | Read/write to session |
| `msf_session_stop` | Terminate session |
| `msf_session_upgrade` | Upgrade shell to meterpreter |

### Job Management

| Tool | Description |
|------|-------------|
| `msf_jobs_list` | List running jobs |
| `msf_job_info` | Get job details |
| `msf_job_stop` | Stop a job |

### Console

| Tool | Description |
|------|-------------|
| `msf_console_create` | Create interactive console |
| `msf_console_list` | List consoles |
| `msf_console_execute` | Run command in console |
| `msf_console_destroy` | Destroy console |

### Database

| Tool | Description |
|------|-------------|
| `msf_db_status` | Check DB connection |
| `msf_db_hosts` | List discovered hosts |
| `msf_db_services` | List discovered services |
| `msf_db_vulns` | List vulnerabilities |
| `msf_db_workspaces` | List workspaces |
| `msf_db_nmap` | Run nmap with DB import |
| `msf_db_import` | Import scan results |

### Payload Generation

| Tool | Description |
|------|-------------|
| `msf_payload_generate` | Generate encoded payload |

## Usage Examples

Once configured, you can ask Claude Code to:

```
"Search for SMB exploits"
"Show me options for exploit/windows/smb/ms17_010_eternalblue"
"List all active sessions"
"Check if 192.168.1.100 is vulnerable to EternalBlue"
"Run an nmap scan on 192.168.1.0/24"
```

## Documentation

### Attack Methodology
- [AD Attack Methodology](docs/ad-attack-methodology.md) - Comprehensive Active Directory attack reference

### GOAD Lab Engagement Writeups
The following documents detail a complete penetration test of the [GOAD (Game of Active Directory)](https://github.com/Orange-Cyberdefense/GOAD) lab environment:

| Document | Description |
|----------|-------------|
| [User to Domain Admin](docs/GOAD-Attack-Path-Blog.md) | S4U2Proxy constrained delegation attack path |
| [Domain Admin to Forest Dominance](docs/GOAD-Forest-Dominance-Blog.md) | ExtraSIDs Golden Ticket attack across trust |
| [Engagement Timeline](docs/GOAD-Engagement-Timeline.md) | Curated 52-command timeline with decision rationale |
| [Full Engagement Log](docs/GOAD-Full-Engagement-Log.md) | Complete 321 commands with timestamps and outputs |
| [North Domain Report](docs/GOAD-North-Engagement-Report.md) | Full engagement report export |

## Security Notice

This tool is intended for **authorized penetration testing and security research only**.

- Only use against systems you own or have explicit written permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## License

MIT
