import typer
import asyncio
from lib.attacks.http_relay import HTTPSCOMRELAY
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'http'
HELP = 'SCOM Web Console NTLM Relay Attack'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    target          : str   = typer.Option(None, "-t",  help="Target SCOM Web Console IP or hostname. "),
    interface       : str   = typer.Option("0.0.0.0", "-i",  help="Interface to listen on."),
    port            : int   = typer.Option(445, "-p",  help="Port to listen on."),
    timeout         : int   = typer.Option(5, "-to", help="Timeout value."),
    verbose         : bool  = typer.Option(False, "-v", help="Enable verbose logging.")
):


    init_logger(verbose)
    http_relay = HTTPSCOMRELAY(target=target, interface=interface, port=port, timeout=timeout, verbose=verbose)
    http_relay.start()
    
