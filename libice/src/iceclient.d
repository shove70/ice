module iceclient;

import std.socket;
import std.conv;
import std.string;
import std.experimental.logger.core;
import std.datetime;
import std.array;

import stunserver, peer, utils, nattype;

class IceClient
{
	const
	{
		string MappedAddress				= "0001";
		string ResponseAddress				= "0002";
		string ChangeRequest				= "0003";
		string SourceAddress				= "0004";
		string ChangedAddress				= "0005";
		string Username						= "0006";
		string Password						= "0007";
		string MessageIntegrity				= "0008";
		string ErrorCode					= "0009";
		string UnknownAttribute				= "000A";
		string ReflectedFrom				= "000B";
		string XorOnly						= "0021";
		string XorMappedAddress				= "8020";
		string ServerName					= "8022";
		string SecondaryAddress				= "8050";  // Non standard extention
	
		// types for a stun message
		string BindRequestMsg				= "0001";
		string BindResponseMsg				= "0101";
		string BindErrorResponseMsg			= "0111";
		string SharedSecretRequestMsg		= "0002";
		string SharedSecretResponseMsg		= "0102";
		string SharedSecretErrorResponseMsg = "0112";
	}
	
	private
	{
		StunServer[] _stunServerList;
		Peer.NATInfo* _natInfo;
	}
	
	this(StunServer[] stunServerList, Peer.NATInfo* natInfo)
	{
		this._stunServerList = stunServerList;
		this._natInfo = natInfo;
		
		getNatInfo();
	}
	
	private bool stunTest(Socket sock, string host, ushort port, string sourceIp, ushort sourcePort, string sendData = string.init)
	{
		Address address = new InternetAddress(host, port);
		string dataLength = rightJustify((cast(int)(sendData.length / 2)).to!string, 4, '0');
		string tranId = genUuid();
		string str_data = join([BindRequestMsg, dataLength, tranId, sendData]);
		ubyte[] data = utils.strToByte_hex(str_data);
		
		bool recvCorr = false;
		while (!recvCorr)
		{
			bool recieved = false;
	        int count = 3;
	        byte[] buffer;
	        
	        while (!recieved)
	        {
	        	long sock_ret = 1;
				try
				{
					sock.connect(address);
					sock_ret = sock.send(data);
					if (sock_ret <= 0)
					{
						throw new Exception(sock.getErrorText());
					}
				}
				catch (Exception e)
				{
					trace(e.msg);
					return false;
				}

				buffer = new byte[2048];
				try
				{
					sock.receiveFrom(buffer);//, address);
					recieved = true;
					if (buffer[0 .. 2] == [0, 0])
					{
						throw new Exception("receive error.");
					}
				}
				catch (Exception e)
				{
	                recieved = false;
	                count--;
	                if (count <= 1)
	                {
	                	return false;
	                }
				}
	        }

	        string msgType = utils.byteToStr_hex(buffer[0 .. 2]);
	        if ((msgType == BindResponseMsg) && (tranId == utils.byteToStr_hex(buffer[4 .. 20])))
	        {
	        	recvCorr = true;
	        	int len_message = utils.byteToStr_hex(buffer[2 .. 4]).to!int(16);
	            int len_remain = len_message;
	            int base = 20;
				while (len_remain)
				{
					string attr_type = utils.byteToStr_hex(buffer[base .. base + 2]);
					int attr_len = utils.byteToStr_hex(buffer[base + 2 .. base + 4]).to!int(16);
					if (attr_type == MappedAddress)
					{
						_natInfo.externalPort = utils.byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16);
						_natInfo.externalIp = join([
										utils.byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					else if (attr_type == SourceAddress)
					{
						_natInfo.sourcePort = utils.byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16);
						_natInfo.sourceIp = join([
										utils.byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					else if (attr_type == ChangedAddress)
					{
						_natInfo.changedPort = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16);
						_natInfo.changedIp = join([
										utils.byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										utils.byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					base = base + 4 + attr_len;
	                len_remain = len_remain - (4 + attr_len);
				}
	        }
		}
		
		return true;
	}

	private void getNatInfo()
	{
		trace("testing the NAT info...");
		string sourceIp = "0.0.0.0";
		ushort sourcePort = 0;
		
//		UdpSocket sock = new UdpSocket();
		Socket sock = new Socket(AddressFamily.INET, SocketType.DGRAM, ProtocolType.UDP);
		sock.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
		sock.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(2));
		sock.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(2));
		sock.bind(new InternetAddress(sourceIp, sourcePort));
		
		_natInfo.localIp = sock.localAddress().toAddrString();
		_natInfo.localPort = sock.localAddress().toPortString().to!ushort;

		string stunServer;
		ushort stunPort;
		bool testOK = false;
		foreach(StunServer server; _stunServerList)
		{
			stunServer = server.host;
			stunPort = server.port;

			if (stunTest(sock, stunServer, stunPort, sourceIp, sourcePort))
			{
				testOK = true;
				break;
			}
		}

		if (!testOK)
		{
			_natInfo.natType = NATType.Blocked;
			sock.close();
			
			return;
		}

		string externalIp = _natInfo.externalIp;
		ushort externalPort = _natInfo.externalPort;
		string changedIp = _natInfo.changedIp;
		ushort changedPort = _natInfo.changedPort;
		string sendData;
		if (_natInfo.externalIp == sourceIp)
		{
			sendData = join([ChangeRequest, "0004", "00000006"]);
			if (stunTest(sock, stunServer, stunPort, sourceIp, sourcePort, sendData))
			{
				_natInfo.natType = NATType.OpenInternet;
			}
			else
			{
				_natInfo.natType = NATType.SymmetricUDPFirewall;
			}
		}
		else
		{
			sendData = join([ChangeRequest, "0004", "00000006"]);
			if (stunTest(sock, stunServer, stunPort, sourceIp, sourcePort, sendData))
			{
				_natInfo.natType = NATType.FullCone;
			}
			else
			{
				if (!stunTest(sock, changedIp, changedPort, sourceIp, sourcePort))
				{
					_natInfo.natType = NATType.ChangedAddressError;
				}
				else
				{
					if ((externalIp == _natInfo.externalIp) && (externalPort == _natInfo.externalPort))
					{
						sendData = join([ChangeRequest, "0004", "00000002"]);
						if (stunTest(sock, changedIp, stunPort, sourceIp, sourcePort, sendData))
						{
							_natInfo.natType = NATType.RestrictNAT;
						}
						else
						{
							_natInfo.natType = NATType.RestrictPortNAT;
						}
					}
					else
					{
						_natInfo.natType = NATType.SymmetricNAT;
					}
				}
			}
		}
		
		sock.close();
	}
}