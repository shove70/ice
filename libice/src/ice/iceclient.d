module ice.iceclient;

import std.stdio;
import std.socket;
import std.conv;
import std.string;
import std.datetime;
import std.array;

import ice.stunserver, ice.utils, ice.natinfo;

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
		UdpSocket _socket;
		StunServer[] _stunServerList;
		NATInfo* _natInfo;
	}
	
	this(UdpSocket socket, StunServer[] stunServerList)
	{
		this._socket = socket;
		this._stunServerList = stunServerList;
	}
	
	private bool stunTest(string host, ushort port, string sourceIp, ushort sourcePort, string sendData = string.init)
	{
		Address address = new InternetAddress(host, port);
		string dataLength = rightJustify((cast(int)(sendData.length / 2)).to!string, 4, '0');
		string tranId = genUuid();	// RFC3489 128bits transaction ID
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
					//_socket.connect(address);
					sock_ret = _socket.sendTo(data, address);
					if (sock_ret <= 0)
					{
						throw new Exception(_socket.getErrorText());
					}
				}
				catch (Exception e)
				{
					writeln(e.msg);
					return false;
				}

				buffer = new byte[2048];
				try
				{
					_socket.receiveFrom(buffer);//, address);
					recieved = true;
					if (buffer[0 .. 2] == [0, 0])
					{
						throw new Exception("Receive error.");
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
						_natInfo.externalPort = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16);
						_natInfo.externalIp = join([
										byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					else if (attr_type == SourceAddress)
					{
						_natInfo.sourcePort = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16);
						_natInfo.sourceIp = join([
										byteToStr_hex(buffer[base +  8 .. base +  9]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base +  9 .. base + 10]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 10 .. base + 11]).to!int(16).to!string, ".",
										byteToStr_hex(buffer[base + 11 .. base + 12]).to!int(16).to!string]);
					}
					else if (attr_type == ChangedAddress)
					{
						_natInfo.changedPort = byteToStr_hex(buffer[base + 6 .. base + 8]).to!ushort(16);
						_natInfo.changedIp = join([
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
		
		//writeln(*_natInfo);
		return true;
	}

	public void getNatInfo(NATInfo* natInfo)
	{
		writeln("Testing the NAT info...");
		
		InternetHost ih = new InternetHost();
		this._natInfo = natInfo;
		
		_natInfo.localIp = _socket.localAddress().toAddrString();
		_natInfo.localPort = _socket.localAddress().toPortString().to!ushort;

		string stunServer;
		ushort stunPort;
		bool testOK = false;
		foreach(StunServer server; _stunServerList)
		{
			if (!ih.getHostByName(server.host))
			{
				continue;
			}

			stunServer = server.host;
			stunPort = server.port;

			if (stunTest(stunServer, stunPort, _natInfo.localIp, _natInfo.localPort))
			{
				testOK = true;
				break;
			}
		}

		if (stunServer == string.init)
		{
			_natInfo.natType = NATType.Uninit;
			writeln("Error.");
			writeln("NAT type: ", _natInfo.natType);
			writeln("No valid stunservers.");
			
			return;
		}

		if (!testOK)
		{
			_natInfo.natType = NATType.Blocked;
			writeln("OK.");
			writeln("NAT type: ", _natInfo.natType);
			
			return;
		}

		string externalIp = _natInfo.externalIp;
		ushort externalPort = _natInfo.externalPort;
		string changedIp = _natInfo.changedIp;
		ushort changedPort = _natInfo.changedPort;
		string sendData;
		if (_natInfo.externalIp == _natInfo.localIp)
		{
			sendData = join([ChangeRequest, "0004", "00000006"]);
			if (stunTest(stunServer, stunPort, _natInfo.localIp, _natInfo.localPort, sendData))
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
			if (stunTest(stunServer, stunPort, _natInfo.localIp, _natInfo.localPort, sendData))
			{
				_natInfo.natType = NATType.FullCone;
			}
			else
			{
				if (!stunTest(changedIp, changedPort, _natInfo.localIp, _natInfo.localPort))
				{
					_natInfo.natType = NATType.ChangedAddressError;
				}
				else
				{
					if ((externalIp == _natInfo.externalIp) && (externalPort == _natInfo.externalPort))
					{
						sendData = join([ChangeRequest, "0004", "00000002"]);
						if (stunTest(changedIp, stunPort, _natInfo.localIp, _natInfo.localPort, sendData))
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
		
		writeln("OK.");
		writeln("NAT type: ", _natInfo.natType);
		writefln("Local ip/port: %s:%d", _natInfo.localIp, _natInfo.localPort);
		writefln("External ip/port: %s:%d", _natInfo.externalIp, _natInfo.externalPort);
	}
}