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
	DEFINITION_IDENTIFIER = "PEEP.ServerPacket"
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

class PeepClientTransport(StackingTransport):

	def __init__(self,protocol,transport):
		self.protocol = protocol
		self.transport = transport
		super().__init__(self.transport)

	def write(self, data):
		print("entering peep client*********************")
		self.protocol.process_upper_layer_data(data)

	def close(self):
		self.protocol.connection_lost(self.protocol)


class PEEPClientProtocol(StackingProtocol):
	def __init__(self):
		self.transport = None
		self.dataSeqStart = 0
		self.receivedDataPackets = [] # in order data collected from server
		self.packets = [] # data packets that haven't been ACKed yet
		self.mostRecentACK = None
		self.session = 0
		self.numDataSent = 0
		self.packetCounter = 0 # the index of the next packet to be written to the wire

	def connection_made(self, transport):
		print("Initialized handshake with  {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.higherProtocol().connection_made(PeepClientTransport(self, transport))
		self.deserializer = PEEPPacket.Deserializer()
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
	
	def process_upper_layer_data(self, data):
		while len(data) > 0:
			chunk = data[:1024]
			data = data[1024:]
			newPkt = PEEPPacket()
			newPkt.Data = chunk
			newPkt.Type = 5
			self.packets.append(newPkt)
			# self.transport.write(newPkt.__serialize__())

			# TODO need to wait for ack and resend if it takes too long
			
	def send(self):
		self.packets[self.packetCounter].SequenceNumber = self.dataSeqStart
		# set checksum
		self.packets[self.packetCounter].Checksum = 0 
		self.packets[self.packetCounter].Checksum = calculateChecksum(self.packets[self.packetCounter].__serialize__())
		self.transport.write(self.packets[self.packetCounter].__serialize__())
		self.packetCounter += 1

	def data_received(self, data):
		self.deserializer.update(data)
		for pkt in self.deserializer.nextPackets():
			if self.session == 0:
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
						print("PEEPPacket being created ################")
						packet.Type = 2
						print("Type updated ################")
						# packet.Acknowledgement = pkt.SequenceNumber + 1
						print("ACK updated ################")
						packet.SequenceNumber = pkt.Acknowledgement
						print("SEQ updated ################")
						self.dataSeqStart = int(pkt.Acknowledgement) + 1
						packet.Checksum = 0
						print("Packet serialized 1! ***************")
						pack = packet.__serialize__()
						packet.Checksum = calculateChecksum(pack)
						pack = packet.__serialize__()
						print("Packet serialized 2! ***************")
						self.session = 1
						print("Type= {}    Acknowledgment = {}    SequenceNumber = {}   Initial Checksum = {}".format(packet.Type, packet.Acknowledgement, packet.SequenceNumber, packet.Checksum))
						print("ACK Packet Sent")
						peeptransport = PeepClientTransport(self, self.transport)
						self.higherProtocol().connection_made(peeptransport)
						self.transport.write(pack)

						if self.session == 1:
							print("IS SESSION 1?????????????????????")
							if self.packetCounter == 0:
								print("RIGHT BEFORE SEND ^^^^^^^^^^^^^^^^^^^^^^^^")
								self.send()
					else:
						connection_lost(self)
				
			elif self.session == 1:
				if pkt.Type == 2:
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
						# self.higherProtocol().connection_made(peeptransport)
						# self.mostRecentACK = pkt
						
						# # if the correct ack is sent back then increment the expected ack for the next packet
						# if self.packets[0].SequenceNumber + len(self.packets[0].Data) == pkt.Acknowledgement:
						self.dataSeqStart = int(pkt.Acknowledgement) + 1
						self.send()

			else:
				connection_lost(self)

			# elif pkt.Type == 5:
			# 	print("Data Packet Received")
			# 	print("Type= {} SequenceNumber = {} Checksum = {}".format(pkt.Type, pkt.SequenceNumber, pkt.Checksum))
			# 	oldChecksum = pkt.Checksum
			# 	pkt.Checksum = 0
			# 	bytes = pkt.__serialize__()
			# 	self.Checksum = oldChecksum
			# 	verify = zlib.adler32(bytes) & 0xffff
			# 	if verify == oldChecksum:
			# 		print("Data Verified")
			# 		# if this is the expected data packet return an ack
			# 		if pkt.SequenceNumber == self.dataSeqStart or pkt.SequenceNumber - len(pkt.Data) == self.receivedDataPackets[-1].SequenceNumber + 1:
			# 			self.receivedDataPackets.append(pkt)
			# 			ack = PEEPPacket()
			# 			ack.Type = 2
			# 			ack.Acknowledgement = pkt.SequenceNumber + len(pkt.Data)
			# 			ack.Checksum = 0
			# 			packet4Bytes = ack.__serialize__()
			# 			ack.Checksum = calculateChecksum(packet4Bytes)
			# 			self.transport.write(ack.__serialize__())
			# 			self.higherProtocol().data_received(pkt.Data)


	def connection_lost(self, exc):
		self.transport = None


Clientfactory = StackingProtocolFactory(lambda: PEEPClientProtocol()) 
