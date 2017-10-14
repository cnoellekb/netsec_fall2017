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
	DEFINITION_IDENTIFIER = "PEEP.ClientPacket"
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

	def __init__(self,protocol,transport):
		self.protocol = protocol
		self.transport = transport
		super().__init__(self.transport)

	def write(self, data):
		print("entering peep client")
		self.protocol.process_upper_layer_data(data)

	def close(self):
		self.protocol.connection_lost(self.protocol)

class PEEPServerProtocol(StackingProtocol):

	def __init__(self):
		self.transport = None
		self.receivedDataPackets = [] # in order data collected from client
		self.synAckSeq = 0
		self.dataSeqStart = 0
		self.packets = [] # packets with chunks of data sent from higher layer to be sent to client
		self.mostRecentACK = None
		self.session = 0

	def connection_made(self, transport):
		print("Received a Handshake Request from {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.higherProtocol().connection_made(PeepServerTransport(self, transport))
		self.deserializer = PEEPPacket.Deserializer()

	# def process_upper_layer_data(self, data):
	# 	seq = random.randrange(9999)
	# 	while len(data) > 0:
	# 		chunk = data[:1024]
	# 		data = data[1024:]
	# 		newPkt = PEEPPacket()
	# 		newPkt.Data = chunk
	# 		newPkt.Type = 5
	# 		newPkt.SequenceNumber = seq
	# 		seq += len(chunk) + 1 # next seq = prev seq + prev data + 1
	# 		# set checksum
	# 		newPkt.Checksum = 0
	# 		packet4Bytes = newPkt.__serialize__()
	# 		newPkt.Checksum = calculateChecksum(packet4Bytes)
	# 		self.packets.append(newPkt)
	# 		self.transport.write(newPkt.__serialize__())

			# TODO need to wait for ack and resend if it takes too long

	def data_received(self, data):
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():
			if self.session == 0:
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
						pack.Acknowledgement = pkt.SequenceNumber
						self.synAckSeq = pkt.SequenceNumber
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
						# peeptransport = PeepServerTransport(self, self.transport)
						# print("CREATING PEEPTRANSPORT SERVERSIDE")
						# self.higherProtocol().connection_made(peeptransport)
						# print("CREATING PEEPTRANSPORT SERVERSIDE2")
						self.dataSeqStart = pkt.SequenceNumber + 1
						print("CREATING PEEPTRANSPORT SERVERSIDE")
						self.session = 1
						print("CREATING PEEPTRANSPORT SERVERSIDE")

						# # if the correct ack is sent back then increment the expected ack for the next packet
						# if self.packets[0].SequenceNumber + len(self.packets[0].Data) == pkt.Acknowledgement:
						# 	self.packets.pop(0)


				else:
					connection_lost(self)

			elif self.session == 1: 
				if pkt.Type == 5:
					print("Data Packet Received")
					print("Type= {}   SequenceNumber     = {}   Checksum = {}".format(pkt.Type, pkt.Acknowledgement, pkt.SequenceNumber, pkt.Checksum))
					oldChecksum = pkt.Checksum
					pkt.Checksum = 0
					bytes = pkt.__serialize__()
					self.Checksum = oldChecksum
					verify = zlib.adler32(bytes) & 0xffff
					if verify == oldChecksum:
						print("Data Verified")
						# if this is the expected data packet return an ack
						if pkt.SequenceNumber == self.dataSeqStart:
							self.receivedDataPackets.append(pkt)
							ack = PEEPPacket()
							ack.Type = 2
							ack.Acknowledgement = pkt.SequenceNumber + len(pkt.Data)
							self.dataSeqStart = ack.Acknowledgement + 1
							ack.Checksum = 0
							packet4Bytes = ack.__serialize__()
							ack.Checksum = calculateChecksum(packet4Bytes)
							self.transport.write(ack.__serialize__())
							self.higherProtocol().data_received(pkt.Data)

			else:
				connection_lost(self)


	def connection_lost(self, reason=None):
		print("Connection end")
		
Serverfactory = StackingProtocolFactory(lambda: PEEPServerProtocol())
