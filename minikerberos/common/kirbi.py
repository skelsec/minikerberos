import base64
from minikerberos.protocol.asn1_structs import KRBCRED, EncKrbCredPart, KrbCredInfo, EncryptedData

class Kirbi:
    def __init__(self, kirbiobj:KRBCRED = None):
        self.kirbiobj = kirbiobj

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

        return Kirbi(KRBCRED(t))
    
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
    
    def __str__(self):
        return self.describe()