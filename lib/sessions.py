#!/usr/bin/env python3
from lib.logger import logger
from msldap.commons.factory import LDAPConnectionFactory
from msldap.commons.exceptions import LDAPBindException
from aiosmb.commons.connection.factory import SMBConnectionFactory
from getpass import getpass
import asyncio



def proto_url(auth_options):
    url_format = {
        "ntlm": f"{{protocol}}+ntlm-password://{{domain}}\\{{username}}:{{password}}@{{dcip}}",
        "nt": f"{{protocol}}+ntlm-nt://{{domain}}\\{{username}}:{{nt}}@{{dcip}}",
        "kerb_password": f"{{protocol}}+kerberos-password://{{domain}}\\{{username}}:{{password}}@{{fqdn}}/?dc={{dcip}}",
        "kerb_rc4": f"{{protocol}}+kerberos-rc4://{{domain}}\\{{username}}:{{nt}}@{{fqdn}}/?dc={{dcip}}",
        "kerb_aes": f"{{protocol}}+kerberos-aes://{{domain}}\\{{username}}:{{aeskey}}@{{fqdn}}/?dc={{dcip}}",
        "kerb_ccache": f"{{protocol}}+kerberos+ccache://{{domain}}\\{{username}}:creds.ccache@127.0.0.1",
        "kerb_pfx": f"{{protocol}}+kerberos+pfx://{{domain}}\\{{username}}:{{password}}@{{dcip}}/?certdata={{pfx}}"          
    }
 
    if "nt" in auth_options and auth_options["nt"]:
        if auth_options["kerberos"]:
            url_type = "kerb_rc4"
        else:
            url_type = "nt"
    elif "aeskey" in auth_options and auth_options["aeskey"]:
        url_type = "kerb_aes"
    elif "pfx" in auth_options and auth_options["pfx"]:
        url_type = "kerb_pfx"
    elif "nopass" in auth_options and auth_options["nopass"]:
        if auth_options["kerberos"]:
            url_type = "kerb_ccache"
    elif "password" in auth_options and auth_options["password"]:
        if auth_options["kerberos"]:
            url_type = "kerb_password"
        else:
            url_type = "ntlm"
    
    format_string = url_format[url_type]
    return format_string.format(**auth_options)


async def ldap_session(auth_options):
    url = proto_url(auth_options)
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
    


async def smb_session(auth_options):
    url = proto_url(auth_options)
    logger.debug(f"Got SMB connection URL: {url}")
    
    try:
        smb_conn = SMBConnectionFactory.from_url(url)
        smb_client = smb_conn.get_connection()
        
        _, err = await smb_client.login()
        if err is not None:
            logger.info(err)
            exit()
        else:
            logger.info("[+] Connected to SMB successfully")
            return smb_client
    except Exception as e:
        logger.info("[-] An unkown error occured.")
        logger.info(e)
    


