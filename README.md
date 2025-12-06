

**SCOMHunter** is a post-exploitation tool for enumerating and attacking System Center Operations Manager (SCOM) infrastructure.


## Features

- **LDAP Enumeration** - Discover SCOM management servers, databases, and related assets
- **NTLM Relay** - Relay authentication to SCOM Web Console and execute commands
- **MSSQL Attacks** - Interact with SCOM databases for privilege escalation
- **DPAPI Decryption** - Decrypt SCOM credentials stored in the database

## Installation

```
git clone https://github.com/garrettfoster13/scomhunter
cd scomhunter
virtualenv --python=python3 .
source bin/activate
pip install -r requirements.txt
```

## Usage
```
➜  scomhunter git:(main) ✗ uv run scomhunter.py -h
SCOMHunter v0.0.1 by @unsigned_sh0rt
                                                                                                                                                                                                                            
 Usage: scomhunter [OPTIONS] COMMAND [ARGS]...                                                                                                                                                                              
                                                                                                                                                                                                                            
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --help  -h        Show this message and exit.                                                                                                                                                                            │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ find    Enumerate LDAP for SCOM assets.                                                                                                                                                                                  │
│ http    SCOM Web Console NTLM Relay Attack                                                                                                                                                                               │
│ mssql   Convert provided sid to hex format and return MSSQL query                                                                                                                                                        │
│ dpapi   Extract DPAPI Protected RunAs Credentials  

```



---

[@garrfoster](https://twitter.com/garrfoster)
