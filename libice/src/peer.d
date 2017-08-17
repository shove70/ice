module peer;

import std.file;
import std.json;
import std.conv;
import std.array;
import std.bitmanip;

import base58;

import utils, stunserver, iceclient, nattype;

class Peer
{
	struct NATInfo
	{
		NATType natType = NATType.Uninit;
		
		string externalIp;
		ushort externalPort = 0;
		string sourceIp;
		ushort sourcePort = 0;
		string changedIp;
		ushort changedPort = 0;
		string localIp;
		ushort localPort = 0;

		void reset()
		{
			natType = NATType.Uninit;
			
			externalIp = string.init;
			externalPort = 0;
			sourceIp = string.init;
			sourcePort = 0;
			changedIp = string.init;
			changedPort = 0;
			localIp = "0.0.0.0";
			localPort = 0;
		}
	}

	public string peerId;
	public NATInfo natInfo;

	this()
	{
		getPeerId();
	}
	
	this(string peerId, string serializedString)
	{
		this.peerId = peerId;

		natInfo.reset();
		ubyte[] buffer = cast(ubyte[])Base58.decode(serializedString);
		int offset = 0;
		
		natInfo.natType = cast(NATType)(buffer.peek!int(offset));
		offset += int.sizeof;
		natInfo.externalIp = utils.ipFromLong(buffer.peek!long(offset));
		offset += long.sizeof;
		natInfo.externalPort = buffer.peek!ushort(offset);
	}
	
	public void getNatInfo(StunServer[] stunServerList)
	{
		natInfo.reset();
		IceClient client = new IceClient(stunServerList, &natInfo);
	}
	
	public string serialize()
	{
		int offset = 0;
		ubyte[] buffer = new ubyte[int.sizeof + long.sizeof + ushort.sizeof];
		int type = natInfo.natType;
		buffer.write!int(type, offset);
		offset += int.sizeof;
		buffer.write!long(utils.ipToLong(natInfo.externalIp), offset);
		offset += long.sizeof;
		buffer.write!ushort(natInfo.externalPort, offset);

		return Base58.encode(cast(byte[])buffer);
	}
	
	private string createPeerId()
	{
		string uuid = utils.genUuid();
		return Base58.encode(utils.strToByte_hex(uuid ~ utils.MD5(uuid)[0 .. 8]));
	}
	
	private bool verifyPeerId(string input)
	{
		try
		{
			byte[] buffer = Base58.decode(input);
			input = utils.byteToStr_hex(buffer);
		}
		catch (Exception e)
		{
			return false;
		}
		
		if (input.length != 40)
		{
			return false;
		}
		
		return (utils.MD5(input[0 .. 32])[0 .. 8] == input[32 .. 40]);
	}

	private void getPeerId()
	{
		string path = "./.caches";
		string fileName = "./.caches/.peerid";
		
		string _peerId;
		
		if (!std.file.exists(path))
		{
			try
			{
				std.file.mkdirRecurse(path);
			}
			catch (Exception e) { }
		}
		
		if (std.file.exists(fileName))
		{
			_peerId = std.file.readText(fileName);
		}
		
		if (!verifyPeerId(_peerId))
		{
			_peerId = createPeerId();
			
			try
			{
				std.file.write(fileName, _peerId);
			}
			catch (Exception e) { }
		}
		
		peerId = _peerId;
	}
}