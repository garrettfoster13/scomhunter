# MSSQL Relay Implementation - Change Summary

## Overview
Successfully migrated the standalone MSSQL query generator into a full NTLM relay attack module that combines SID conversion, query generation, and relay functionality.

## Changes Made

### 1. Created New MSSQL Relay Attack Module
**File:** `lib/attacks/mssql_relay.py`

**Key Components:**
- `SCOMMSSQLRelayClient` - Extends Impacket's MSSQLRelayClient for NTLM relay
- `SCOMMSSQLAttackClient` - Executes SQL queries after successful authentication
- `MSSQLSCOMRELAY` - Main orchestrator class that manages the relay server

**Features:**
- Automatic SID to hex conversion (supports both string SIDs and hex SIDs)
- Three operation modes:
  - **Update/Insert** (default): Adds user to SCOM admin role
  - **Delete**: Removes user from SCOM admin role  
  - **List**: Lists current members of SCOM admin role
- Built-in query generation for all operations
- NTLM relay server setup and management

### 2. Updated MSSQL Command Interface
**File:** `lib/commands/mssql.py`

**New Command Structure:**
```bash
scomhunter mssql -t <target> -s <sid> [options]
```

**Required Arguments:**
- `-t, --target` - Target MSSQL server

**Optional Arguments:**
- `-s, --sid` - SID to add/remove (required for update/delete, optional for list)
- `-i, --interface` - Listening interface (default: 0.0.0.0)
- `-p, --port` - Listening port (default: 445)
- `--timeout` - Connection timeout (default: 5)
- `-v, --verbose` - Enable verbose logging

**Operation Modes (mutually exclusive):**
- `-u, --update` - Add user to admin role (default)
- `-d, --delete` - Remove user from admin role
- `-l, --list` - List current role members

### 3. Removed Old Files
**Deleted:** `lib/attacks/mssql.py`
- Old standalone module that only generated queries
- Functionality migrated to new relay module

### 4. Updated Documentation
**File:** `README.md`
- Updated command description
- Added comprehensive usage examples
- Documented all options and operation modes

## SQL Queries Generated

### Insert (Update Mode)
```sql
Use OperationsManager; 
INSERT INTO AzMan_Role_SIDMember (RoleID, MemberSID) 
Values ('1', <hex_sid>);
```

### Delete Mode
```sql
Use OperationsManager; 
DELETE FROM AzMan_Role_SIDMember 
WHERE RoleID = '1' AND MemberSID = <hex_sid>;
```

### List Mode
```sql
Use OperationsManager; 
SELECT * FROM AzMan_Role_SIDMember 
WHERE RoleID = 1;
```

## Usage Examples

### Add User to SCOM Admin Role
```bash
scomhunter mssql -t mssql.corp.com -s S-1-5-21-xxx-xxx-xxx-1234
```

### Remove User from SCOM Admin Role
```bash
scomhunter mssql -t mssql.corp.com -s S-1-5-21-xxx-xxx-xxx-1234 -d
```

### List Current Admin Role Members
```bash
scomhunter mssql -t mssql.corp.com -l
```

### Custom Interface and Port
```bash
scomhunter mssql -t 192.168.1.10:1433 -s S-1-5-21-xxx-xxx-xxx-1234 -i 192.168.1.50 -p 8445
```

## How It Works

1. User runs the command with target MSSQL server and SID
2. Tool converts SID to hex format (if needed)
3. Builds appropriate SQL query based on operation mode
4. Sets up SMB relay server on specified interface/port
5. Waits for incoming NTLM authentication
6. Relays authentication to target MSSQL server
7. On successful auth, executes the SQL query
8. Reports results and shuts down

## Testing Recommendations

1. Test SID conversion with various formats
2. Verify relay functionality with valid NTLM authentication
3. Test all three operation modes (update, delete, list)
4. Verify error handling for invalid inputs
5. Test with different MSSQL server configurations
6. Verify cleanup on keyboard interrupt

## Dependencies

- impacket (for NTLM relay functionality)
- typer (for CLI interface)
- Standard Python libraries

## Notes

- The tool requires elevated privileges to bind to port 445 (default)
- Alternative ports can be specified with `-p` flag
- SID can be provided in either string format (S-1-5-21-...) or hex format (0x...)
- List mode does not require a SID parameter