module iceclient;

import std.random;
import std.socket;
import std.uuid;
import std.conv;
import std.string;
import std.experimental.logger.core;
import std.datetime;
import std.array;

import stunserver, peer;

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
		
		string Blocked						= "Blocked";
		string OpenInternet					= "Open Internet";
		string FullCone						= "Full Cone";
		string SymmetricUDPFirewall			= "Symmetric UDP Firewall";
		string RestrictNAT					= "Restrict NAT";
		string RestrictPortNAT				= "Restrict Port NAT";
		string SymmetricNAT					= "Symmetric NAT";
		string ChangedAddressError			= "Meet an error, when do Test1 on Changed IP and Port";
	}
	
	private
	{
		StunServer[] stunServerList;
		string trackerHost;
		ushort trackerPort;
		string[string] _NAT_Info;
	}
	
	@property public string[string] NAT_Info()
	{
		return this._NAT_Info;
	}
	
	this(StunServer[] stunServerList, string trackerHost, ushort trackerPort)
	{
		this.stunServerList = stunServerList;
		this.trackerHost = trackerHost;
		this.trackerPort = trackerPort;
		
		_NAT_Info = ["externalIp": "", "externalPort": "0", "sourceIp": "", "sourcePort": "0", "changedIp": "", "changedPort": "0", "natType": ""];
		getNatInfo();
	}
	
	private string genUuid()	// RFC3489 128bits transaction ID
	{
		Xorshift192 gen;
		gen.seed(unpredictableSeed);
		auto uuid = randomUUID(gen);
		return uuid.toString.replace("-", "").toUpper();
	}
	
	private ubyte[] strToByte_hex(string input)
	{
		Appender!(ubyte[]) app;
		for (int i; i < input.length; i += 2)
		{
			app ~= input[i .. i + 2].to!ubyte(16);
		}
		return app.data;
	}
	
	private string byteToStr_hex(byte[] buffer)
	{
		Appender!string app;
		foreach (b; buffer)
		{
			app ~= rightJustify(b.to!string(16).toUpper(), 2, '0');
		}
		return app.data;
	}
	
	private bool stunTest(Socket sock, string host, ushort port, string sourceIp, ushort sourcePort, string sendData = string.init)
	{
		Address address = new InternetAddress(host, port);
		string dataLength = rightJustify((cast(int)(sendData.length / 2)).to!string, 4, '0');
		string tranId = genUuid();
		string str_data = join([BindRequestMsg, dataLength, tranId, sendData]);
		ubyte[] data = strToByte_hex(str_data);
		
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

	        string msgType = byteToStr_hex(buffer[0 .. 2]);
	        if ((msgType == BindResponseMsg) && (tranId == byteToStr_hex(buffer[4 .. 20])))
	        {
	        	recvCorr = true;
	        	int len_message = byteToStr_hex(buffer[2 .. 4]).to!int(16);
	            int len_remain = len_message;
	            int base = 20;
				while (len_remain)
				{
					string attr_type = byteToStr_hex(buffer[base .. base + 2]);
					int attr_len = byteToStr_hex(buffer[base + 2 .. base + 4]).to!int(16);
					if (attr_type == MappedAddress)
					{
						_NAT_Info["externalPort"] = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16).to!string;
						_NAT_Info["externalIp"] = join([
										byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					else if (attr_type == SourceAddress)
					{
						_NAT_Info["sourcePort"] = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16).to!string;
						_NAT_Info["sourceIp"] = join([
										byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					else if (attr_type == ChangedAddress)
					{
						_NAT_Info["changedPort"] = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16).to!string;
						_NAT_Info["changedIp"] = join([
										byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
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

		string stunServer;
		ushort stunPort;
		bool testOK = false;
		foreach(StunServer server; stunServerList)
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
			_NAT_Info["natType"] = Blocked;
			sock.close();
			
			return;
		}

		string externalIp = _NAT_Info["externalIp"];
		ushort externalPort = _NAT_Info["externalPort"].to!ushort;
		string changedIp = _NAT_Info["changedIp"];
		ushort changedPort = _NAT_Info["changedPort"].to!ushort;
		string sendData;
		if (_NAT_Info["externalIp"] == sourceIp)
		{
			sendData = join([ChangeRequest, "0004", "00000006"]);
			if (stunTest(sock, stunServer, stunPort, sourceIp, sourcePort, sendData))
			{
				_NAT_Info["natType"] = OpenInternet;
			}
			else
			{
				_NAT_Info["natType"] = SymmetricUDPFirewall;
			}
		}
		else
		{
			sendData = join([ChangeRequest, "0004", "00000006"]);
			if (stunTest(sock, stunServer, stunPort, sourceIp, sourcePort, sendData))
			{
				_NAT_Info["natType"] = FullCone;
			}
			else
			{
				if (!stunTest(sock, changedIp, changedPort, sourceIp, sourcePort))
				{
					_NAT_Info["natType"] = ChangedAddressError;
				}
				else
				{
					if ((externalIp == _NAT_Info["externalIp"]) && (externalPort == _NAT_Info["externalPort"].to!ushort))
					{
						sendData = join([ChangeRequest, "0004", "00000002"]);
						if (stunTest(sock, changedIp, stunPort, sourceIp, sourcePort, sendData))
						{
							_NAT_Info["natType"] = RestrictNAT;
						}
						else
						{
							_NAT_Info["natType"] = RestrictPortNAT;
						}
					}
					else
					{
						_NAT_Info["natType"] = SymmetricNAT;
					}
				}
			}
		}
		
		sock.close();
	}
}