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
│ mssql   Convert provided sid to hex format and return MSSQL query                         │
│ dpapi   Extract DPAPI Protected RunAs Credentials                                         │
╰───────────────────────────────────────────────────────────────────────────────────────────╯

```
# References

TBD

