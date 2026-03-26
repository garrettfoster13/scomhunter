import typer
import asyncio
from lib.attacks.mssql import MSSQL
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'mssql'
HELP = 'Convert provided sid to hex format and return MSSQL query'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    # auth args
    sid             : str   = typer.Option(None, "-s",  help="SID of user to elevate"),
    delete          : bool  = typer.Option(False, '-d',help='Create a delete query for cleanup'),
    verbose         : bool  = typer.Option(False, '-v',help='Enable Verbose Logging'),
    ):


    init_logger(verbose)
    scomhunter = MSSQL(sid=sid, delete=delete, verbose=verbose)
    scomhunter.run()
    