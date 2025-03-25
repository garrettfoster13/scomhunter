import typer
import asyncio
from lib.attacks.dpapi import DPAPIHUNTER
from lib.logger import init_logger

app = typer.Typer()
COMMAND_NAME = 'dpapi'
HELP = 'Extract DPAPI Protected RunAs Credentials'

@app.callback(no_args_is_help=True, invoke_without_command=True)

def main(
    # auth args
    username        : str   = typer.Option(None, "-u",  help="Username"),
    password        : str   = typer.Option(None, '-p',  help="Password"),
    hashes          : str   = typer.Option(None, "-hashes",metavar="LMHASH:NTHASH", help="LM and NT hashes, format is LMHASH:NTHASH"),
    aes             : str   = typer.Option(None, '-aes', metavar="HEX KEY", help='AES key to use for Kerberos Authentication (128 or 256 bits)'), 
    kerberos        : bool  = typer.Option(False, "-k", help='Use Kerberos authentication'),
    no_pass         : bool  = typer.Option(False, "-no-pass", help="don't ask for password (useful for -k)"),
    
    #target args
    domain          : str   = typer.Option(..., '-d',  help="Domain "),
    dc_ip           : str   = typer.Option(..., '-dc-ip',  help = "IP address of domain controller"),
    ldaps           : bool  = typer.Option(False, '-ldaps', help='Use LDAPS instead of LDAP'),
    fqdn            : str  = typer.Option(False, '-fqdn', help="FQDN of target host"),

    #other
    verbose         : bool  = typer.Option(False, '-v',help='Enable Verbose Logging'),
):


    init_logger(verbose)
    dpapihunter = DPAPIHUNTER(username=username, password=password, hashes=hashes, aes=aes, kerberos=kerberos,
                            no_pass=no_pass, domain=domain, dc_ip=dc_ip, ldaps=ldaps, fqdn=fqdn, verbose=verbose)
    asyncio.run(dpapihunter.run())
    
    