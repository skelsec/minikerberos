#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import asyncio

from minikerberos.protocol.asn1_structs import KerberosResponse
from minikerberos.common.constants import KerberosSocketType

class AIOKerberosClientSocket:
	def __init__(self, target):
		self.target = target
		#ip, port = 88, soc_type = KerberosSocketType.TCP
		self.soc_type = target.protocol
		self.dst_ip = target.ip
		self.dst_port = int(target.port)
		#self.soc = None
		self.reader = None
		self.writer = None
		
	def __str__(self):
		t = '===KerberosSocket AIO===\r\n'
		t += 'soc_type: %s\r\n' % self.soc_type
		t += 'dst_ip: %s\r\n' % self.dst_ip
		t += 'dst_port: %s\r\n' % self.dst_port
		
		return t		
		
	def get_addr_str(self):
		return '%s:%d' % (self.dst_ip, self.dst_port)
		
	async def create_soc(self):
		if self.soc_type == KerberosSocketType.TCP:
			self.reader, self.writer = await asyncio.open_connection(self.dst_ip, self.dst_port)
		
		elif self.soc_type == KerberosSocketType.UDP:
			raise Exception('UDP not implemented!')
			
		else:
			raise Exception('Unknown socket type!')
			
	async def sendrecv(self, data, throw = False):
		await self.create_soc()
		try:
			if self.soc_type == KerberosSocketType.TCP:				
				length = len(data).to_bytes(4, byteorder = 'big', signed = False)
				self.writer.write(length + data)
				await self.writer.drain()
				
				t = await self.reader.readexactly(4)
				length = int.from_bytes(t, byteorder = 'big', signed = False)
				data = await self.reader.readexactly(length)
				
			elif self.soc_type == KerberosSocketType.UDP:
				raise Exception('Not implemented!')
			
			krb_message = KerberosResponse.load(data)
			return krb_message
		finally:
			self.writer.close()
			self.reader = None
			self.writer = None
		
		