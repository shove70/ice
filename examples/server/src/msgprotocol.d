module msgprotocol;

import std.bitmanip;
import std.array;
import std.string;
import std.conv;
import std.typecons;

/**
protocol rule:
	len ~ cmd, ~ from, ~ to, ~ content
	
	cmd:
	
	(1) Peer to server
	01: report a peer info (for client self)
	02: request all peers info from server.
	03: say to send (forward)
	(2) Peer to peer
	10: say to send
*/

struct Packet
{
	int cmd;
	string fromPeerId;
	string toPeerId;
	string content;
}

class MsgProtocol
{
	int cmd;
	string fromPeerId;
	string toPeerId;
	string content;
	
	static ubyte[] build(Packet packet)
	{
		return build(packet.cmd, packet.fromPeerId, packet.toPeerId, packet.content);
	}
	
	// with len head
	static ubyte[] build(int cmd, string fromPeerId, string toPeerId, string content)
	{
		ubyte[] data = cast(ubyte[])join([cmd.to!string, ",", fromPeerId, ",", toPeerId, ",", content]);
		ubyte[] buffer = new ubyte[4];
		buffer.write!int(cast(int)data.length, 0);
		buffer ~= data;
		
		return buffer;
	}
	
	static Nullable!Packet parse(ubyte[] buffer)	// without len head
	{
		string data = cast(string)buffer;
		string[] strs = data.split(",");
		
		if (strs.length != 4)
		{
			return Nullable!Packet();
		}
		
		Packet packet;
		
		try
		{
			packet.cmd = strs[0].to!int;
		}
		catch (Exception e)
		{
			return Nullable!Packet();
		}
		
		packet.fromPeerId = strs[1];
		packet.toPeerId = strs[2];
		packet.content = strs[3];
		
		return Nullable!Packet(packet);
	}
}