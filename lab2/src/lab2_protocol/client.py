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
		("SequenceNumber", UINT32({Optional: True})),
		("Checksum", UINT16),
		("Acknowledgement", UINT32({Optional: True})),
		("Data", BUFFER({Optional: True}))
		]

def calculateChecksum(pc):
	return zlib.adler32(pc) & 0xffff

class MyClientProtocol(asyncio.Protocol):
	def __init__(self):
		self.transport = None
	def connection_made(self, transport):
		print("Handshake Successful: Connected to {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.deserializer = PacketType.Deserializer()

	def data_received(self, data):
		print("At the Client")

	def connection_lost(self, exc):
		self.transport = None


class EchoControl:
	def buildProtocol(self):
		return MyClientProtocol()

class passthrough1(StackingProtocol):

	def __init__(self):
		self.transport = None
		super().__init__

	def connection_made(self,transport):
		print("Passthrough Layer 1-Connection Made Called")
		self.transport = transport
		self.higherProtocol().connection_made(self.transport)

	def data_received(self,data):
		print("Passthrough Layer 1-Connection Made Called")
		self.higherProtocol().data_received(data)

  
class PEEPClientProtocol(StackingProtocol):
	def __init__(self):
		self.transport = None
	def connection_made(self, transport):
		print("Initialized handshake with  {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.deserializer = PacketType.Deserializer()
		pack = PEEPPacket()
		pack.Type = 0
		pack.SequenceNumber = random.randrange(9999)
		pack.Checksum = 0
		packet4Bytes = pack.__serialize__()
		pack.Checksum = calculateChecksum(packet4Bytes)
		packet4Bytes = pack.__serialize__()
		print("Type= {}    SequenceNumber = {}   Checksum = {}".format(pack.Type, pack.SequenceNumber, pack.Checksum))
		self.transport.write(packet4Bytes)
		print("SYN Packet Sent")
		
	def data_received(self, data):
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():
			if pkt.Type == 1:
				print("SYN-ACK Packet Received")
				print("Type= {}    Acknowledgment = {}    SequenceNumber = {}   Initial Checksum = {}".format(pkt.Type, pkt.Acknowledgement, pkt.SequenceNumber, pkt.Checksum))
				oldChecksum = pkt.Checksum
				pkt.Checksum = 0
				bytes = pkt.__serialize__()
				verify = zlib.adler32(bytes) & 0xffff
				if verify == oldChecksum:
					print("SYN-ACK Packet Verified")
					packet = PEEPPacket()
					packet.Type = 2
					packet.Acknowledgement = pkt.SequenceNumber + 1
					packet.SequenceNumber = pkt.Acknowledgement
					packet.Checksum = 0
					pack = packet.__serialize__()
					packet.Checksum = calculateChecksum(pack)
					pack = packet.__serialize__()
					self.transport.write(pack)
					print("Type= {}    Acknowledgment = {}    SequenceNumber = {}   Initial Checksum = {}".format(packet.Type, packet.Acknowledgement, packet.SequenceNumber, packet.Checksum))
					print("ACK Packet Sent")
					self.higherProtocol().connection_made(self.transport)
				else:
					connection_lost(self)
			else:
				connection_lost(self)

	def connection_lost(self, exc):
		self.transport = None


#f = StackingProtocolFactory(lambda: passthrough1(), lambda: passthrough2())
#ptConnector = playground.Connector(protocolStack=f)
#playground.setConnector("passthrough", ptConnector)
#loop = asyncio.get_event_loop()
#conn = EchoControl()
#coro = playground.getConnector("passthrough").create_playground_connection(conn.buildProtocol, "2020.20.2.2", 101)
#client = loop.run_until_complete(coro)
#loop.run_forever()
#loop.close()
Clientfactory = StackingProtocolFactory(lambda: PEEPClientProtocol()) 
