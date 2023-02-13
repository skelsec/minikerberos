from minikerberos.protocol.asn1_structs import EncTicketPart, AD_IF_RELEVANT
from minikerberos.protocol.external.rpcrt import TypeSerialization1
from minikerberos.protocol.external.pac import PACTYPE, PAC_INFO_BUFFER, \
	PAC_CREDENTIAL_INFO, PAC_CREDENTIAL_DATA, NTLM_SUPPLEMENTAL_CREDENTIAL
from minikerberos import logger
from minikerberos.protocol.encryption import Key, _enctype_table

def get_NT_from_PAC(pkinit_tkey, decticket:EncTicketPart, truncated_keydata=None):
		adIfRelevant = AD_IF_RELEVANT.load(decticket['authorization-data'][0]['ad-data'])		
		if truncated_keydata is None:
			truncated_keydata = pkinit_tkey
		if truncated_keydata is None:
			raise Exception("Missing tkey! Is this a PKINIT session?")
		key = Key(18, truncated_keydata)
		pacType = PACTYPE(adIfRelevant.native[0]['ad-data'])
		buff = pacType['Buffers']
		creds = []
		for bufferN in range(pacType['cBuffers']):
			infoBuffer = PAC_INFO_BUFFER(buff)
			data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
			logger.debug("TYPE 0x%x" % infoBuffer['ulType'])
			if infoBuffer['ulType'] == 2:
				credinfo = PAC_CREDENTIAL_INFO(data)
				newCipher = _enctype_table[credinfo['EncryptionType']]

				out = newCipher.decrypt(key, 16, credinfo['SerializedData'])
				type1 = TypeSerialization1(out)
				# I'm skipping here 4 bytes with its the ReferentID for the pointer
				newdata = out[len(type1)+4:]
				pcc = PAC_CREDENTIAL_DATA(newdata)
				for cred in pcc['Credentials']:
					credstruct = NTLM_SUPPLEMENTAL_CREDENTIAL(b''.join(cred['Credentials']))
					if credstruct['NtPassword'] != b'\x00'*16:
						creds.append(('NT', credstruct['NtPassword'].hex()))
					if credstruct['LmPassword'] != b'\x00'*16:
						creds.append(('LM', credstruct['LmPassword'].hex()))

			buff = buff[len(infoBuffer):]
		
		return creds