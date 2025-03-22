#!/usr/bin/env python3
from lib.logger import logger
from msldap.commons.factory import LDAPConnectionFactory
from msldap.commons.exceptions import LDAPBindException
from getpass import getpass
import asyncio



def ldap_url(auth_options):
    protocol = "ldaps" if auth_options.get("ldaps", False) else "ldap"
    url_format = {
        "ldap_ntlm": f"{protocol}+ntlm-password://{{domain}}\\{{username}}:{{password}}@{{dcip}}",
        "ldap_nt": f"{protocol}+ntlm-nt://{{domain}}\\{{username}}:{{nt}}@{{dcip}}",
        "ldap_kerb_password": f"{protocol}+kerberos-password://{{domain}}\\{{username}}:{{password}}@{{fqdn}}/?dc={{dcip}}",
        "ldap_kerb_rc4": f"{protocol}+kerberos-rc4://{{domain}}\\{{username}}:{{nt}}@{{fqdn}}/?dc={{dcip}}",
        "ldap_kerb_aes": f"{protocol}+kerberos-aes://{{domain}}\\{{username}}:{{aeskey}}@{{fqdn}}/?dc={{dcip}}",
        "ldap_kerb_ccache": f"{protocol}+kerberos+ccache://{{domain}}\\{{username}}:creds.ccache@127.0.0.1",
        "ldap_kerb_pfx": f"{protocol}+kerberos+pfx://{{domain}}\\{{username}}:{{password}}@{{dcip}}/?certdata={{pfx}}"          
    }
    
    if "nt" in auth_options and auth_options["nt"]:
        if auth_options["kerberos"]:
            url_type = "ldap_kerb_rc4"
        else:
            url_type = "ldap_nt"
    elif "aeskey" in auth_options and auth_options["aeskey"]:
        url_type = "ldap_kerb_aes"
        
        
    elif "pfx" in auth_options and auth_options["pfx"]:
        url_type = "ldap_kerb_pfx"
    elif "nopass" in auth_options and auth_options["nopass"]:
        if auth_options["kerberos"]:
            url_type = "ldap_kerb_ccache"
    elif "password" in auth_options and auth_options["password"]:
        if auth_options["kerberos"]:
            url_type = "ldap_kerb_password"
        else:
            url_type = "ldap_ntlm"
    
    format_string = url_format[url_type]
    return format_string.format(**auth_options)


async def ldap_session(auth_options):
    url = ldap_url(auth_options)
    logger.debug(f"Got LDAP connection URL: {url}")
    
    try:
        ldap_conn = LDAPConnectionFactory.from_url(url)
        ldap_client = ldap_conn.get_client()
        
        _, err = await ldap_client.connect()
        if err is not None:
            logger.info(err)
            exit()
        else:
            logger.info("[+] Connected to LDAP successfully")
            return ldap_client
    except Exception as e:
        logger.info("[-] An unkown error occured.")
        logger.info(e)
    


