from scapy.all import *
from scapy.layers.inet import IP, TCP

# VARIABLES
src = '192.168.219.239'  # Replace with your computer's IP address
dst615 = '192.168.219.40'  # REF615 IP address
dst620 = '192.168.219.30'  # REF620 IP address
sport = 15464  # Source from Zenon program
dport = 102  # MMS Server standard port

##########################
## CONSTRUCT SYN PACKET ##
##########################

# Construct initial SYN packet
ip615 = IP(src=src,dst=dst615)
SYN = TCP(sport=sport,dport=dport,flags='S',seq=0)
syn_packet_615 = ip615/SYN

########################
## DO 3-WAY HANDSHAKE ##
########################

# Send SYN request and wait for SYN-ACK
# Upon receiving SYN-ACK, store into variable SYN-ACK

SYNACK615 = sr1(syn_packet_615)

# Construct ACK packet (last packet of 3-way handshake)
ACK615 = TCP(sport=sport,dport=dport,flags='A',seq=SYNACK615.ack,
             ack=SYNACK615.seq + 1)

# Send ACK packet
send(ip615/ACK615)

#####################################################
#####################################################
## THIS IS WHERE FURTHER COMMUNICATION NEEDS TO GO ##
## (there appear to be several more communication  ##
##  exchanges which take place before an MMS trip  ##
##  message can be properly sent)                  ##
#####################################################
#####################################################

##########################
## COTP CONNECT REQUEST ##
##########################

# Construct TCP packet
tcp = TCP(sport=sport,dport=dport,flags='PA',seq=1,ack=1)


# Custom TPKT class
class TPKT(Packet):
    name = "TPKT"
    fields_desc = [XByteField("Version", 3),
                   XByteField("Reserved", 0),
                   ShortField("Length", 22)]


# Custom COTP class
class COTPConnectionRequest(Packet):
    name = "COTP"
    fields_desc = [ByteField("Length", 17),
                   ByteField("PDUType", 0xE0),  # Connection Request PDU type
                   ShortField("DestinationReference", 0),
                   ShortField("SourceReference", 1),
                   ByteField("Flags", 0),
                   ByteField("ParameterCodeTPDUSize", 0xC0),
                   ByteField("TPDULength", 1),
                   ByteField("TPDUSize", 10),
                   ByteField("ParameterCodeDSTTSAP", 0xC2),
                   ByteField("DSTTSAPLength", 2),
                   ShortField("DestinationTSAP", 1),
                   ByteField("ParameterCodeSRCTSAP", 0xC1),
                   ByteField("SRCTSAPLength", 2),
                   ShortField("SourceTSAP", 0)]


# Construct TPKT encapsulation packet and COTP packet
tpkt = TPKT()
cotp = COTPConnectionRequest()

# Send request to both devices
send(ip615/tcp/tpkt/cotp)

###########################
## MMS ASSOCIATE REQUEST ##
###########################


class COTPDataTransfer(Packet):
    name = "COTP"
    fields_desc = [ByteField("Length", 2),
                   ByteField("PDUType", 0xF0),  # Data Transfer PDU type
                   ByteField("TPDUNumber", 0x80)]


class SessionConnect(Packet):
    name = "Session"
    fields_desc = [ByteField("SPDUType", 0x0D),  # Connect PDU type
                   ByteField("Length", 182),
                   ByteField("ConnectAcceptItem", 0x05),
                   ByteField("ConnectAcceptItemLength", 6),
                   ByteField("ProtocolOptions", 0x13),
                   ByteField("ProtocolOptionsLength", 1),
                   ByteField("ProtocolOptionsFlags", 0x00),
                   ByteField("VersionNumber", 0x16),
                   ByteField("VersionNumberLength", 1),
                   ByteField("VersionNumberFlags", 0x02),
                   ByteField("SessionRequirement", 0x14),
                   ByteField("SessionRequirementLength", 2),
                   ShortField("SessionRequirementFlags", 0x0002),
                   ByteField("CallingSessionSelector", 0x33),
                   ByteField("CallingSessionSelectorLength", 2),
                   ShortField("CallingSessionSelectorFlags", 0x0001),
                   ByteField("CalledSessionSelector", 0x34),
                   ByteField("CalledSessionSelectorLength", 2),
                   ShortField("CalledSessionSelectorFlags", 0x0001),
                   ByteField("SessionUserData", 0xC1),
                   ByteField("SessionUserDataLength", 160)]


class PresentationNegotiation(Packet):
    name = "Presentation"
    fields_desc = [ThreeBytesField("Unknown1", 0x31819D),
                   ShortField("CPType", 0xA003),
                   ShortField("ModeSelector", 0x8001),
                   ByteField("ModeValue", 0x01),
                   ThreeBytesField("Unknown2", 0xA28195),
                   ShortField("NormalModeParameters", 0x8104),
                   NBytesField("CallingPresentationSelector", 0x00000001, 4),
                   ShortField("Unknown3", 0x8204),
                   NBytesField("CalledPresentationSelector", 0x00000001, 4),
                   ShortField("Unknown4", 0xA423),
                   NBytesField("ContextListItem1", 0x300F0201, 4),
                   ByteField("PresentationContextIdentifier1", 0x01),
                   ShortField("Unknown5", 0x0604),
                   NBytesField("AbstractSyntaxName1", 0x52010001, 4),
                   ShortField("Unknown6", 0x3004),
                   ShortField("TransferSyntaxNameList1", 0x0602),
                   ShortField("TransferSyntaxName1", 0x5101),
                   NBytesField("ContextListItem2", 0x30100201, 4),
                   ByteField("PresentationContextIdentifier2", 0x03),
                   ShortField("Unknown7", 0x0605),
                   NBytesField("AbstractSyntaxName2", 0x28CA220201, 5),
                   ShortField("Unknown8", 0x3004),
                   ShortField("TransferSyntaxNameList2", 0x0602),
                   ShortField("TransferSyntaxName2", 0x5101),
                   ShortField("Unknown9", 0x6162),
                   NBytesField("UserData", 0x30600201, 4),
                   ByteField("PresentationContextIdentifier3", 0x01),
                   ShortField("Unknown10", 0xA05B)]


class ApplicationControlService(Packet):
    name = "Application"
    fields_desc = [ShortField("Unknown1", 0x6059),
                   NBytesField("aarq", 0xA1070605, 4),
                   NBytesField("ASOContextName", 0x28CA220203, 5),
                   ShortField("Unknown2", 0xA207),
                   ShortField("CalledAPTitle", 0x0605),
                   NBytesField("CalledAPTitleForm2", 0x2987670101, 5),
                   ShortField("Unknown3", 0xA303),
                   ShortField("CalledAEQualifier", 0x0201),
                   ByteField("CalledASOQualifierForm", 0x0C),
                   ShortField("Unknown4", 0xA606),
                   ShortField("CallingAPTitle", 0x0604),
                   NBytesField("CallingAPTitleForm2", 0x29018767, 4),
                   ShortField("Unknown5", 0xA703),
                   ShortField("CallingAEQualifier", 0x0201),
                   ByteField("CallingASOQualifierForm", 0x0C),
                   ShortField("Unknown6", 0xBE33),
                   ShortField("UserInformation", 0x2831),
                   ShortField("AssociationData", 0x0602),
                   ShortField("DirectReference", 0x5101),
                   ShortField("Unknown7", 0x0201),
                   ByteField("IndirectReference", 0x03),
                   ShortField("Unknown8", 0xA028)]


class MMSAssociateRequest(Packet):
    name = "MMS"
    fields_desc = [ShortField("Unknown1", 0xA826),
                   ShortField("InitiateRequestPDU", 0x8003),
                   ThreeBytesField("LocalDetailCalling", 0x00FDE8),
                   ShortField("Unknown2", 0x8101),
                   ByteField("ProposedMaxServOutstandingCalling", 0x0A),
                   ShortField("Unknown3", 0x8201),
                   ByteField("ProposedMaxServOutstandingCalled", 0x0A),
                   ShortField("Unknown4", 0x8301),
                   ByteField("ProposedDataStructureNestingLevel", 0x05),
                   ShortField("Unknown5", 0xA416),
                   ShortField("MMSInitRequestDetail", 0x8001),
                   ByteField("ProposedVersionNumber", 0x01),
                   ShortField("Unknown6", 0x8103),
                   ByteField("Padding1", 0x05),
                   ShortField("ProposedParameterCBB", 0xF100),
                   ShortField("Unknown7", 0x820C),
                   ByteField("Padding2", 0x03),
                   NBytesField("ServicesSupportedCalling", 0xEE1C00000408000079EF18, 11)]


tpkt.setfieldval("Length", 0x00BF)
tcp.seq = 23  # Hard coded seq, since ack length is always 22
tcp.ack = 23
cotp = COTPDataTransfer()
session = SessionConnect()
presentation = PresentationNegotiation()
application = ApplicationControlService()
mms = MMSAssociateRequest()

send(ip615/tcp/tpkt/cotp/session/presentation/application/mms)

###########################
## CONSTRUCT TRIP PACKET ##
###########################

# Add IP edits
ip615.flags = 'DF'
ip615.frag = 0
ip615.ttl = 128

# Construct TCP layer
tcp = TCP()
tcp.sport = sport
tcp.dport = dport
tcp.seq = 214  # Hard coded seq
tcp.ack = 214
tcp.dataofs = 5
tcp.reserved = 0
tcp.flags = 'PA'
tcp.window = 514
tcp.urgptr = 0

# Add TPKT edits
tpkt.setfieldval("Length", 0x0078)


# Construct Session layer 1 and 2
class SessionDataTransfer(Packet):
    name = "Session"
    fields_desc = [ByteField("SPDUType", 0x01),
                   ByteField("Length", 0x0)]


# Construct Presentation layer
class PresentationDataTransfer(Packet):
    name = "Presentation"
    fields_desc = [ShortField("Unknown", 0x616B),
                   NBytesField("PDVList", 0x30690201, 4),
                   ByteField("PresentationContextIdentifier", 0x03),
                   ShortField("PresentationDataValues", 0xA064)]


# Construct MMS layer
class MMSSetDataValueRequest(Packet):
    name = "MMS"
    fields_desc = [ShortField("Unknown1", 0xA062),
                   ShortField("ConfirmedRequestPDU", 0x0201),
                   ByteField("InvokeID", 0x35),
                   ShortField("Unknown2", 0xA55D),
                   ShortField("ConfirmedServiceRequest", 0xA027),
                   NBytesField("ListOfVariableItem", 0x3025A023, 4),
                   ShortField("VariableSpecificationName", 0xA121),
                   ShortField("DomainSpecific", 0x1A0A),
                   NBytesField("DomainID", 0x5245463631354354524C, 10),  # REF615CTRL in ASCII
                   ShortField("Unknown3", 0x1A13),
                   NBytesField("ItemID", 0x4342435357493124434F24506F732453424F77, 19),  # CBCSWI1$CO$Pos$SBOw in ASCII
                   ShortField("Unknown4", 0xA032),
                   ShortField("ListOfData", 0xA230),
                   ShortField("DataStructure", 0x8301),
                   ByteField("CtlVal", 0x01),
                   ShortField("Unknown5", 0xA217),
                   ShortField("Origin", 0x8501),
                   ByteField("OriginCategory", 0x02),
                   ShortField("Unknown6", 0x8912),
                   NBytesField("OriginIdentifier", 0x277A656E6F6E3A20574B5330323437393027, 18),  # 'zenon: WKS024790' in ASCII
                   ShortField("Unknown7", 0x8601),
                   ByteField("CtlNum", 0x02),
                   ShortField("Unknown8", 0x9108),
                   NBytesField("UTCTimeSeconds", 0x66315443, 4),  # Apr 30, 2024 20:27:47.527108669 UTC
                   ThreeBytesField("UTCTimeNanoseconds", 0x86F098),
                   ByteField("UTCTimeFlags", 0x00),
                   ShortField("Unknown9", 0x8301),
                   ByteField("Test", 0x00),
                   ShortField("Unknown10", 0x8402),
                   ByteField("Padding", 0x06),
                   ByteField("Check", 0x00)]


def set_mms_time(request):
    nanoseconds = time.time_ns()
    seconds = nanoseconds // 1000000000
    nanoseconds = nanoseconds - seconds * 1000000000
    request.setfieldval("UTCTimeSeconds", seconds)
    request.setfieldval("UTCTimeNanoseconds", nanoseconds)


session1 = SessionDataTransfer()
session2 = SessionDataTransfer()
presentation = PresentationDataTransfer()
mms = MMSSetDataValueRequest()
set_mms_time(mms)

# Construct trip packet
packet = ip615 / tcp / tpkt / cotp / session1 / session2 / presentation / mms

######################
## SEND TRIP PACKET ##
######################

# Trip packet part 1
send(packet)
#sniff(filter="tcp", count=1)
time.sleep(1)

tcp.seq = 334
tcp.ack = 334
mms.setfieldval("ItemID", 0x4342435357493124434F24506F73244f706572)  # CBCSWI1$CO$Pos$Oper in ASCII
mms.setfieldval("InvokeID", 0x34)
set_mms_time(mms)

packet = ip615 / tcp / tpkt / cotp / session1 / session2 / presentation / mms

# Trip packet part 2
send(packet)
