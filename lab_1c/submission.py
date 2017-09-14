import asyncio
import hashlib

from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToProtocol

class RC(PacketType):
	DEFINITION_IDENTIFIER = "lab.gaur.RequestChallenge"
	DEFINITION_VERSION = "1.0"
	FIELDS = [
		("qid", UINT32)
		]
class Challenge(PacketType):
	DEFINITION_IDENTIFIER = "lab.gaur.Challenge"
	DEFINITION_VERSION = "1.0"
	FIELDS = [
		("qidentity", UINT32),
		("question", STRING)
		]
class Authentication(PacketType):
	DEFINITION_IDENTIFIER = "lab.gaur.Authentication"
	DEFINITION_VERSION = "1.0"
	FIELDS = [
		("qidentity", UINT32),
		("hashvalue", STRING)
		]
class Connection(PacketType):
	DEFINITION_IDENTIFIER = "lab.gaur.Connection"
	DEFINITION_VERSION = "1.0"
	FIELDS = [
		("qidentity", UINT32),
		("confirmation", BOOL)
		]

def reverse(strtoreverse):
	return strtoreverse[::-1]

def encrypt(challengeword):
	hash_object = hashlib.sha512(reverse(challengeword))
	hash_word = hash_object.hexdigest()
	return hash_word
def phrase():
	script=b"this is the question"
	return script
def ans():
	answer = encrypt(phrase())
	#answer = encrypt(b"trial wrong answer")
	return answer

def sendChallenge():
	packet2 = Challenge()
	packet2.qidentity = 3
	packet2.question = phrase()
	packet2Bytes = packet2.__serialize__()
	return packet2Bytes

def sendAuthentication():
	packet3 = Authentication()
	packet3.qidentity = 2
	packet3.hashvalue = encrypt(phrase())
	packet3Bytes = packet3.__serialize__()
	return packet3Bytes

def sendConnection():
	packet4 = Connection()
	packet4.qidentity = 4
	packet4.confirmation = True
	packet4Bytes = packet4.__serialize__()
	return packet4Bytes

def sendRejection():
	packet4 = Connection()
	packet4.qidentity = 4
	packet4.confirmation = False
	packet4Bytes = packet4.__serialize__()
	return packet4Bytes
def hiyo():
	packet1 = RC()
	packet1.qid=1
	packet1Bytes = packet1.__serialize__()
	return packet1Bytes

class MyServerProtocol(asyncio.Protocol):
	def __init__(self):
		self.transport = None
	def connection_made(self, transport):
		self.transport = transport
		self.deserializer = PacketType.Deserializer()
	def data_received(self, data):
		print("reached here")
		verify = encrypt(b"this is the question")
		self.deserializer.update(data)
		print("To the Server:")
		for pkt in self.deserializer.nextPackets():
			if isinstance(pkt, RC):
				print("Hello Packet received")
				self.transport.write(sendChallenge())
			elif isinstance(pkt, Authentication):
				print("Authentication Packet received")
				if ans() == pkt.hashvalue:
					self.transport.write(sendConnection())
					#print ("Server Confirms:True")
				else:
					self.transport.write(sendRejection()) 
					#print("Server Confirms:False")
	def connection_lost(self, exc):
		self.transport = None

class MyClientProtocol(asyncio.Protocol):
	def __init__(self):
		self.transport = None
	def connection_made(self, transport):
		self.transport = transport
		self.deserializer = PacketType.Deserializer()
		self.transport.write(hiyo())
	def data_received(self, data):
		print("At the Client")
		self.deserializer.update(data)		
		for pkt in self.deserializer.nextPackets():
			if isinstance(pkt,Challenge):
				print("Challenge Received")
				self.transport.write(sendAuthentication())
			elif isinstance(pkt,Connection):
				print("Client received: Server says: {}".format(pkt.confirmation))
	def connection_lost(self, exc):
		self.transport = None

def basicUnitTest():

	asyncio.set_event_loop(TestLoopEx())
	clientProtocol = MyClientProtocol()
	serverProtocol = MyServerProtocol()
	cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(clientProtocol, serverProtocol)
	serverProtocol.connection_made(sTransport)
	clientProtocol.connection_made(cTransport)

if __name__=="__main__":
	basicUnitTest()
