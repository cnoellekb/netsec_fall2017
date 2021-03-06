import asyncio
import zlib
import playground
from playground.network.common import StackingProtocol,StackingTransport,StackingProtocolFactory
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32,UINT8,UINT16, STRING, BUFFER, BOOL
from playground.network.packet.fieldtypes.attributes import Optional
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToProtocol
import random

class PEEPPacket(PacketType):
	DEFINITION_IDENTIFIER = "PEEP.Packet"
	DEFINITION_VERSION = "1.0"

	FIELDS = [
		("Type", UINT8),
		("SequenceNumber", UINT32 ({Optional: True})),
		("Checksum", UINT16),
		("Acknowledgement", UINT32({Optional: True})),
		("Data", BUFFER({Optional: True}))
		]

def calculateChecksum(pc):
	return zlib.adler32(pc) & 0xffff

class PeepServerTransport(StackingTransport):

	def __init__(self,protocol, transport):
		self.protocol=protocol
		self.transport = transport
		super().__init__(self.transport)

	def write(self, data):
		self.protocol.write(data)


class PEEPServerProtocol(StackingProtocol):

	def __init__(self):
		self.transport = None
        
	def connection_made(self, transport):
		print("Received a Handshake Request from {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.deserializer = PacketType.Deserializer()
	def data_received(self, data):
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():
			if pkt.Type == 0:
				print("SYN Packet Received")
				print("Type= {}    SequenceNumber = {}   Checksum = {}".format(pkt.Type, pkt.SequenceNumber, pkt.Checksum))
				oldChecksum = pkt.Checksum
				pkt.Checksum = 0
				bytes = pkt.__serialize__()
				self.Checksum = oldChecksum
				verify = zlib.adler32(bytes) & 0xffff
				if verify == oldChecksum:
					print("SYN Packet Verified")
					pack = PEEPPacket()
					pack.Type = 1
					pack.Acknowledgement = pkt.SequenceNumber + 1
					pack.SequenceNumber = random.randrange(10)
					pack.Checksum = 0
					packet4Bytes = pack.__serialize__()
					pack.Checksum = calculateChecksum(packet4Bytes)
					packet4Bytes = pack.__serialize__()
					print("Type= {}    Acknowledgment = {}    SequenceNumber = {}   Checksum = {}".format(pack.Type, pack.Acknowledgement, pack.SequenceNumber, pack.Checksum))
					self.transport.write(packet4Bytes)
					print("SYN-ACK Packet Sent")
				else:
					connection_lost(self)
			elif pkt.Type == 2:
				print("ACK Packet Received")
				print("Type= {}    Acknowledgment = {}    SequenceNumber = {}   Checksum = {}".format(pkt.Type, pkt.Acknowledgement, pkt.SequenceNumber, pkt.Checksum))
				oldChecksum = pkt.Checksum
				pkt.Checksum = 0
				bytes = pkt.__serialize__()
				self.Checksum = oldChecksum
				verify = zlib.adler32(bytes) & 0xffff
				if verify == oldChecksum:
					print("ACK Packet Verified")
					peeptransport = PeepServerTransport(self, self.transport)
					higherTransport = StackingTransport(peeptransport)
					self.higherProtocol().connection_made(higherTransport)
				else:
					connection_lost(self)
			else:
				connection_lost(self)


	def connection_lost(self, reason=None):
		print("Connection end")
		
Serverfactory = StackingProtocolFactory(lambda: PEEPServerProtocol())
