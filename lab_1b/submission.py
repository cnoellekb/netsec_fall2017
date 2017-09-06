from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL

def basicUnitTest():
	class RC(PacketType):
		DEFINITION_IDENTIFIER = "lab1b.gaur.RequestChallenge"
		DEFINITION_VERSION = "1.0"

		FIELDS = [
			]

	class Challenge(PacketType):
		DEFINITION_IDENTIFIER = "lab1b.gaur.Challenge"
		DEFINITION_VERSION = "1.0"
	
		FIELDS = [
			("qidentity", UINT32),
			("question", STRING)
			]
	
	class Authentication(PacketType):
		DEFINITION_IDENTIFIER = "lab1b.gaur.Authentication"
		DEFINITION_VERSION = "1.0"
	
		FIELDS = [
			("qidentity", UINT32),
			("hashvalue", BUFFER)
			]

	class Connection(PacketType):
		DEFINITION_IDENTIFIER = "lab1b.gaur.Connection"
		DEFINITION_VERSION = "1.0"

		FIELDS = [
			("identity", UINT32),
			("confirmation", BOOL)
			]


	packet1 = RC()
	packet1Bytes = packet1.__serialize__()
	packet1a = RC.Deserialize(packet1Bytes)
	assert packet1 == packet1a

	packet2 = Challenge()
	packet2.qidentity = 10
	packet2.question = "this is the question"
	packet2Bytes = packet2.__serialize__()
	packet2a=Challenge.Deserialize(packet2Bytes)
	assert packet2 == packet2a

	#packet8 = Challenge()
	#packet8.qidentity = -10
	#packet8.question = "this is the question"
	#packet2Bytes = packet8.__serialize__()
	#packet8a=Challenge.Deserialize(packet8Bytes)
	#assert packet8 == packet8a

	packet3 = Authentication()
	packet3.qidentity = 10
	packet3.hashvalue = b"18C907ADF5843DE4EA9F0E6B48539D5A0F960DE280A064C114C8C7D4A1F4CE2997E8645DFBAB43BA71A8B77E4C40836F1CC3E4A99C562716E76D5570D0A74E58"
	packet3Bytes = packet3.__serialize__()
	packet3a=Authentication.Deserialize(packet3Bytes)
	assert packet3 == packet3a

	#packet7 = Authentication()
	#packet7.qidentity = -10
	#packet7.hashvalue = b"18C907ADF5843DE4EA9F0E6B48539D5A0F960DE280A064C114C8C7D4A1F4CE2997E8645DFBAB43BA71A8B77E4C40836F1CC3E4A99C562716E76D5570D0A74E58"
	#packet7Bytes = packet7.__serialize__()
	#packet7a=Challenge.Deserialize(packet7Bytes)
	#assert packet7 == packet7a
	
	packet4 = Connection()
	packet4.identity = 10
	packet4.confirmation = "true"
	packet4Bytes = packet4.__serialize__()
	packet4a=Connection.Deserialize(packet4Bytes)
	assert packet4 == packet4a
	
	packet6 = Connection()
	packet6.identity = 10
	packet6.confirmation = "false"
	packet6Bytes = packet6.__serialize__()
	packet6a=Connection.Deserialize(packet6Bytes)
	assert packet6 == packet6a
	
	#packet5 = Confirmation()
	#packet5.identity = -10
	#packet5.confirmation = true
	#packet5Bytes = packet5.__serialize__()
	#packet5a=Confirmation.Deserialize(packet5Bytes)
	#assert packet5 == packet5a

if __name__=="__main__":
	basicUnitTest()
