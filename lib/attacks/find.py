import asyncio
from lib.sessions import ldap_session, ImpacketSMB
from lib.logger import logger
from lib.scripts.helpers import HELPERS

class SCOMHUNTER:
    
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
        self.protocol = "ldaps" if ldaps else "ldap"
        self.fqdn = fqdn

        #other
        self.verbose = verbose
        self.ldap_session = None
                

   
    async def ldapsession(self):
        """Build the msldap URL and return the connection"""
        auth_options = {
            "domain": self.domain,
            "username": self.username,
            "password": self.password,
            "nt": self.hashes,
            "aes": self.aes,
            "dcip": self.dc_ip,
            "fqdn": self.fqdn,  
            "protocol": self.protocol,
            "kerberos": self.kerberos,
            "nopass": self.no_pass
        }
    
        ldap_client = await ldap_session(auth_options)         # Generate the LDAP URL
        return auth_options, ldap_client     
    
    async def find_mgmtserver(self):
        """Find SCOM Management Servers. All will have the MSOMHSvc ServicePrincipalName"""
        ldap_filter = "(serviceprincipalname=MSOMHSvc/*)"
        attributes = '*' #paged_search in msldap doesn't have a dnshostname attribute, need to PR
        logger.info("[*] Searching for SCOM Management Servers")
        try:
            _entry = self.ldap_session.pagedsearch(ldap_filter, attributes)
            _results = await HELPERS.parse_entry(_entry)
            if _results:
                for result in _results:
                    hostname = spn = None
                    if "dNSHostName" in result['attributes']:
                        hostname = result['attributes']['dNSHostName']
                    if "servicePrincipalName" in result['attributes']:
                        spn = result['attributes']['servicePrincipalName']    
                    mgmt_server = {'Hostname': hostname, 'ServicePrincipalNames':spn}
                    HELPERS.insert_to_db(table_name="ManagementServers", data=mgmt_server)
                return True
            else:
                logger.info("[-] Could not find any Managment Servers in LDAP. SCOM doesn't appear to be in use.")
        except Exception as e:
            logger.info(f"Something went wrong {e}")
            
    async def find_sdkuser(self):
        """Find SCOM Data Access Service Accounts if they're in use"""
        ldap_filter = "(&(serviceprincipalname=MSOMSdkSvc/*)(samaccounttype=805306368)(!(samaccounttype=805306370)))"
        attributes = '*' 
        logger.info("[*] Searching for SCOM SDK Service Accounts")
        try:
            _entry = self.ldap_session.pagedsearch(ldap_filter, attributes)
            _results = await HELPERS.parse_entry(_entry)
            if _results:
                for result in _results:
                    username = spn = desc = pwdlastset = None       
                    if "userPrincipalName" in result['attributes']:
                        username = result['attributes']['userPrincipalName']
                    if "servicePrincipalName" in result['attributes']:
                        spn = result['attributes']['servicePrincipalName']
                    if "description" in result['attributes']:
                        desc = result['attributes']['description']
                    if "pwdLastSet" in result['attributes']:
                        pwdlastset = result['attributes']['pwdLastSet']
                    users = {'Username': username, 'Description': desc,'ServicePrincipalNames':spn, 'pwdLastSet': pwdlastset}
                    HELPERS.insert_to_db(table_name="Users", data=users)
                return True
            else:
                logger.info("[-] Could not find any SDK user accounts in LDAP.")
        except Exception as e:
            logger.info(f"Something went wrong {e}")
            
    async def run(self):
        HELPERS.create_db()
        if not self.ldap_session:                               
            auth_options, self.ldap_session = await self.ldapsession()        
        
        mgmt_servers = await self.find_mgmtserver()
        if mgmt_servers:
            HELPERS.show_table("ManagementServers")
        
        sdk_users = await self.find_sdkuser()
        if sdk_users:
            HELPERS.show_table("Users")



