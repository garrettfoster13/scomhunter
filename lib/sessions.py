#!/usr/bin/env python3
from lib.logger import logger
from msldap.commons.factory import LDAPConnectionFactory
from msldap.commons.exceptions import LDAPBindException
from aiosmb.commons.connection.factory import SMBConnectionFactory
from getpass import getpass
import asyncio
from io import BytesIO
import ntpath

#impacket stuff for DPAPI
from impacket.smbconnection import SMBConnection, SessionError


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
    


class ImpacketSMB:
    def __init__(self, auth_options: dict):

        self.username = auth_options['username']
        self.password = auth_options['password'] #password
        self.domain = auth_options['domain']
        self.hashes = auth_options['nt']
        self.aesKey = auth_options['aes']
        self.target = auth_options['dcip']
        self.kdcHost = auth_options['fqdn']
        self.doKerberos = auth_options['kerberos']
        self.no_pass = auth_options['nopass'] #nopass
        self.lmhash = ""
        self.nthash = ""

        #
        self.smb_conn = None

        if self.hashes:
            self.nthash = self.hashes
        
    
        self.connect()

    def connect(self) -> SMBConnection:
        try:
            logger.debug(f"[*] Establishing SMB connection to {self.target}")
            self.smb_conn = SMBConnection(self.target, self.target)
            if self.doKerberos:
                logger.debug("[*] Performing Kerberos login")
                self.smb_conn.kerberosLogin(self.username, self.password, self.domain, self.lmhash,
                                               self.nthash, self.aesKey, self.kdcHost)
            else:
                logger.debug("[*] Performing NTLM login")
                self.smb_conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        except OSError as e:
            if str(e).find("Connection reset by peer") != -1:
                logger.info(f"SMBv1 might be disabled on {self.target}")
            if str(e).find('timed out') != -1:
                raise Exception(f"The connection is timed out. Port 445/TCP port is closed on {self.target}")
            return None
        except SessionError as e:
            if str(e).find('STATUS_NOT_SUPPORTED') != -1:
                raise Exception('The SMB request is not supported. Probably NTLM is disabled.')
        except Exception as e:
                logger.debug(str(e))
        
        #logger.debug("[*] SMB Connection Established!")
        return self.smb_conn
    
    
    def disconnect(self):
        logger.debug(f"[*] Closing SMB connection to {self.target}")
        self.smb_conn.logoff()

    def getFileContent(self, share, path, filename):
        content = None
        try:
            fh = BytesIO()
            filepath = ntpath.join(path,filename)
            self.smb_conn.getFile(share, filepath, fh.write)
            content = fh.getvalue()
            fh.close()
        except:
            return None
        return content