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
		self.protocol.process_upper_layer_data(data)

	def close(self):
		self.protocol.connection_lost(self.protocol)

  
class PEEPClientProtocol(StackingProtocol):
	def __init__(self):
		self.transport = None
		self.dataSeqStart = 0
		self.recievedBytes = [] # in order data collected from server
		self.expectedAck = 0
		self.expectedAcks = {} # maps expected ack to the index of this packet in self.packets
		self.packets = [] # packets with chunks of data sent from higher layer to be sent to server

	def connection_made(self, transport):
		print("Initialized handshake with  {}".format(transport.get_extra_info("peername")))
		self.transport = transport
		self.higherProtocol().connection_made(PeepClientTransport(self, transport))
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
	
	def process_upper_layer_data(self, data):
		chunks = []
		seq = self.dataSeqStart+1
		while len(data) > 0:
			chunks.append(data[:1024])
			data = data[1024:]

		for (i, chunk) in enumerate(chunks):
			newPkt = PEEPPacket()
			newPkt.Data = chunk
			newPkt.Type = 5
			newPkt.SequenceNumber = seq
			seq += len(chunk) + 1 # next seq = prev seq + prev data + 1
			# set checksum
			newPkt.Checksum = 0
			packet4Bytes = newPkt.__serialize__()
			newPkt.Checksum = calculateChecksum(packet4Bytes)
			self.packets.append(newPkt)
			self.expectedAcks[seq - 1] = i
			# if we try to send this packet 5 times and it still doesn't work then close the connection
			# for j in range(5):
			# 	oldExpectedAck = self.expectedAck
			# 	self.transport.write(newPkt.__serialize__())
			# 	await asyncio.sleep(1)
			# 	if self.expectedAck > oldExpectedAck:
			# 		break
			# 	elif j == 4:
			# 		self.connection_lost(self)
			self.transport.write(newPkt.__serialize__())

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
					self.dataSeqStart = int(packet.SequenceNumber)
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
					peeptransport = PeepClientTransport(self, self.transport)
					self.higherProtocol().connection_made(peeptransport)
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
					
					# if the correct ack is sent back then increment the expected ack for the next packet
					if self.expectedAck == pkt.Acknowledgement:
						nextPkt = self.packets[self.expectedAcks[self.expectedAck] + 1]
						self.expectedAck += len(nextPkt) + 1

			elif pkt.Type == 5:
				print("Data Packet Received")
				print("Type= {} SequenceNumber = {} Checksum = {}".format(pkt.Type, pkt.SequenceNumber, pkt.Checksum))
				oldChecksum = pkt.Checksum
				pkt.Checksum = 0
				bytes = pkt.__serialize__()
				self.Checksum = oldChecksum
				verify = zlib.adler32(bytes) & 0xffff
				if verify == oldChecksum:
					print("Data Verified")
					# if this is the expected data packet return an ack
					if True or pkt.SequenceNumber - len(pkt.Data) == self.recievedBytes[-1].SequenceNumber + 1:
						self.recievedBytes.append(pkt.Data)
						ack = PEEPPacket()
						ack.Type = 2
						ack.Acknowledgement = pkt.SequenceNumber + len(pkt.Data)
						ack.Checksum = 0
						self.transport.write(ack.__serialize__())
						self.higherProtocol().data_received(pkt.__serialize__())
						self.recievedBytes = []

						# if the incoming data is piggybacked
						if pkt.Acknowledgement != "Unset Packet Field":
							# if the correct ack is sent back then increment the expected ack for the next packet
							if self.expectedAck == pkt.Acknowledgement:
								nextPkt = self.packets[self.expectedAcks[self.expectedAck] + 1]
								self.expectedAck += len(nextPkt) + 1
			else:
				connection_lost(self)

	def connection_lost(self, exc):
		self.transport = None


Clientfactory = StackingProtocolFactory(lambda: PEEPClientProtocol()) 
