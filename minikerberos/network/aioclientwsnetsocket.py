
#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import asyncio

from minikerberos.protocol.asn1_structs import KerberosResponse
from minikerberos.common.constants import KerberosSocketType

from pyodidewsnet.client import WSNetworkTCP

class AIOKerberosClientWSNETSocket:
	def __init__(self, target):
		self.target = target
		self.out_queue = None
		self.in_queue = None

		self.proxy_client = None
		self.proxy_task = None
		
	def get_addr_str(self):
		return '%s:%d' % (self.target.ip, self.target.port)

	async def sendrecv(self, data):
		self.out_queue = asyncio.Queue()
		self.in_queue = asyncio.Queue()
		self.proxy_client = WSNetworkTCP(self.target.ip, int(self.target.port), self.in_queue, self.out_queue)
		_, err = await self.proxy_client.run()
		if err is not None:
			raise err

		length = len(data).to_bytes(4, byteorder = 'big', signed = False)
		await self.out_queue.put(length+data)

		resp_data = b''
		resp_data_len = -1
		while True:
			data, err = await self.in_queue.get()
			if data is None:
				break
			if err is not None:
				raise err
			resp_data += data
			if resp_data_len == -1:
				if len(resp_data) > 4:
					resp_data_len = int.from_bytes(resp_data[:4], byteorder = 'big', signed = False)
					if resp_data_len == 0:
						raise Exception('Returned data length is 0! This means the server did not understand our message')
			
			if resp_data_len != -1:
				if len(resp_data) == resp_data_len + 4:
					resp_data = resp_data[4:]
					break
				elif len(resp_data) > resp_data_len + 4:
					raise Exception('Got too much data somehow')
				else:
					continue
		
		await self.out_queue.put(None)
		if resp_data == b'':
			raise Exception('Connection returned no data!')
		
		krb_message = KerberosResponse.load(resp_data)
		return krb_message

		
	def __str__(self):
		t = '===AIOKerberosClientProxySocket AIO===\r\n'
		t += 'target: %s\r\n' % self.target
		
		return t