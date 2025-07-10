import base64
from minikerberos.protocol.asn1_structs import KRBCRED, EncKrbCredPart, KrbCredInfo, EncryptedData, KERB_DMSA_KEY_PACKAGE

class Kirbi:
    def __init__(self, kirbiobj:KRBCRED = None, encpart = None):
        # the encpart is optional and will not affect the kirbiobj
        self.kirbiobj = kirbiobj
        self.encpart = encpart

    """
    if isinstance(data, bytes):
            kirbi = KRBCRED.load(data).native
        elif isinstance(data, dict):
            kirbi = data
        elif isinstance(data, KRBCRED):
            kirbi = data.native
        else:
            raise Exception('Unknown data type! %s' % type(data))
    """
    @staticmethod
    def from_file(fpath):
        with open(fpath, 'rb') as f:
            return Kirbi.from_bytes(f.read())
        
    def to_file(self, fpath):
        with open(fpath, 'wb') as f:
            f.write(self.kirbiobj.dump())
    
    
    @staticmethod
    def from_bytes(data):
        k = Kirbi()
        k.kirbiobj = KRBCRED.load(data)
        return k
    
    def to_bytes(self):
        return self.kirbiobj.dump()
    
    @staticmethod
    def from_b64(b64):
        return Kirbi.from_bytes(base64.b64decode(b64))
    
    def to_b64(self):
        return base64.b64encode(self.kirbiobj.dump()).decode()
    
    @staticmethod
    def from_hex(hexdata):
        return Kirbi.from_bytes(bytes.fromhex(hexdata))
    
    def to_hex(self):
        return self.kirbiobj.dump().hex()
    
    @staticmethod
    def from_ticketdata(tgt_or_tgs, encpart):
        ci = {}
        ci['key'] = encpart['key']
        ci['prealm'] = tgt_or_tgs['crealm']
        ci['pname'] = tgt_or_tgs['cname']
        ci['flags'] = encpart['flags']
        ci['authtime'] = encpart['authtime']
        ci['starttime'] = encpart['starttime']
        ci['endtime'] = encpart['endtime']
        ci['renew-till'] = encpart['renew-till']
        ci['srealm'] = encpart['srealm']
        ci['sname'] = encpart['sname']

        ti = {}
        ti['ticket-info'] = [KrbCredInfo(ci)]

        te = {}
        te['etype']  = 0
        te['cipher'] = EncKrbCredPart(ti).dump()

        t = {}
        t['pvno'] = 5
        t['msg-type'] = 22
        t['enc-part'] = EncryptedData(te)
        t['tickets'] = [tgt_or_tgs['ticket']]

        return Kirbi(KRBCRED(t), encpart)
    
    @staticmethod
    def format_kirbi(data, n = 100):
        kd = base64.b64encode(data).decode()
        return '    ' + '\r\n    '.join([kd[i:i+n] for i in range(0, len(kd), n)])
    
    def format(self, n = 100):
        return self.format_kirbi(self.kirbiobj.dump(), n=n)

    def describe(self):        
        t = '\r\n'
        for ticket in self.kirbiobj.native['tickets']:
            t += 'Realm        : %s\r\n' % ticket['realm']
            t += 'Sname        : %s\r\n' % '/'.join(ticket['sname']['name-string'])

        if self.kirbiobj.native['enc-part']['etype'] == 0:
            cred = EncKrbCredPart.load(self.kirbiobj.native['enc-part']['cipher']).native
            cred = cred['ticket-info'][0]
            username = cred.get('pname')
            if username is not None:
                username = '/'.join(username['name-string'])
            flags = cred.get('flags')
            if flags is not None:
                flags = ', '.join(flags)

            t += 'UserName     : %s\r\n' % username
            t += 'UserRealm    : %s\r\n' % cred.get('prealm')
            t += 'StartTime    : %s\r\n' % cred.get('starttime')
            t += 'EndTime      : %s\r\n' % cred.get('endtime')
            t += 'RenewTill    : %s\r\n' % cred.get('renew-till')
            t += 'Flags        : %s\r\n' % flags
            t += 'Keytype      : %s\r\n' % cred['key']['keytype']
            t += 'Key          : %s\r\n' % base64.b64encode(cred['key']['keyvalue']).decode()
        
        if self.encpart is not None:
            t += 'EncryptedPAData:\r\n'
            if 'encrypted-pa-data' in self.encpart and self.encpart['encrypted-pa-data'] is not None:
                for encpadata in self.encpart['encrypted-pa-data']:
                    if encpadata['padata-type'] == 171:
                        keypackage = KERB_DMSA_KEY_PACKAGE.load(encpadata['padata-value'])
                        t += '   [171] KeyPackage:\r\n'
                        for line in keypackage.describe().split('\n'):
                            t += '      %s\r\n' % line

        t += 'EncodedKirbi : \r\n\r\n'
        t += self.format()
        return t
    
    def get_username(self):
        if self.kirbiobj.native['enc-part']['etype'] == 0:
            cred = EncKrbCredPart.load(self.kirbiobj.native['enc-part']['cipher']).native
            cred = cred['ticket-info'][0]
            username = cred.get('pname')
            if username is not None:
                return '/'.join(username['name-string'])
        return None
    
    def dmsa_get_previous_keys(self):
        if self.encpart is None:
            return []
        if 'encrypted-pa-data' not in self.encpart or self.encpart['encrypted-pa-data'] is None:
            return []
        prevkeys = []
        for encpadata in self.encpart['encrypted-pa-data']:
            if encpadata['padata-type'] == 171:
                keypackage = KERB_DMSA_KEY_PACKAGE.load(encpadata['padata-value'])
                for previous_key in keypackage['previous-keys']:
                    prevkeys.append((previous_key['keytype'].native, previous_key['keyvalue'].native.hex()))
        return prevkeys
    
    def __str__(self):
        return self.describe()