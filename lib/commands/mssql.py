import typer
import asyncio
from lib.attacks.mssql import MSSQL
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'mssql'
HELP = 'Convert provided sid to hex format and return MSSQL query'

@app.callback(no_args_is_help=True, invoke_without_command=True)
def main(
    sid             : str   = typer.Option(None, "-s",  help="SID of user to elevate"),
    reverse         : str   = typer.Option(None, "-r", "--reverse", help="Decode binary SID to canonical format"),
    delete          : bool  = typer.Option(False, '-d',help='Create a delete query for cleanup'),
    verbose         : bool  = typer.Option(False, '-v',help='Enable Verbose Logging'),
    ):

    init_logger(verbose)
    scomhunter = MSSQL(sid=sid, reverse=reverse, delete=delete, verbose=verbose)
    scomhunter.run()
    