module ice.packet;

import std.stdio;
import std.bitmanip;
import std.array;
import std.string;
import std.conv;
import std.typecons;

import ice.utils, ice.natinfo;

enum Cmd
{
	ReportPeerInfo				= 1,
	RequestAllPeers				= 2,	
	PostMessageDirect			= 3,
	PostMessageForward			= 4,
	RequestMakeHoleDirect		= 5,
	RequestMakeHoleForward		= 6,
	ResponseMakeHoleDirect		= 7,
	ResponseMakeHoleForward		= 8,
	Heartbeat					= 9
}

/**
protocol rule (TLV):
	magic_number(ushort) ~ total_len(ushort) ~ cmd(byte) ~ sender_nattype(byte) ~ len(byte)+from(string) ~ len(byte)+to(string) ~ len(ushort)+data(string) ~ ushort(hash(all)[0..4])
	
	cmd:
	
	1: report a peer info (for client self)	-> server reply: 1,"",to,""
	2: request all peers from server.		-> server reply: 2,"",to,"id|info;id|info;..."
	3: postmessage(direct send)				-> none
	4: postmessage(forward)					-> server forward: 4,from,to,data
	5: request make hole(direct)			-> peerother reply peer: 7
	6: request make hole(forward)			-> server forward: 6,from,to,data -> peerother reply(two):	-> peer:   7
																										-> server: 7 -> server to peer: 8
	9: heartbeat							-> none
*/

struct Packet
{
	Cmd cmd;
	NATType fromNatType;
	string fromPeerId;
	string toPeerId;
	ubyte[] data;
	
	static ubyte[] build(ushort magicNumber, Cmd cmd, NATType fromNatType, string fromPeerId, string toPeerId, ubyte[] data = null)
	{
		ubyte[] from_buf = cast(ubyte[])fromPeerId;
		ubyte[] to_buf = cast(ubyte[])toPeerId;
		ubyte[] data_buf = cast(ubyte[])data;
		ulong total_len = from_buf.length + to_buf.length + data_buf.length + 7;
		
		assert(total_len <= 65503);
		
		ubyte[] buffer = new ubyte[4];
		buffer.write!ushort(magicNumber, 0);
		buffer.write!ushort(cast(ushort)total_len, 2);
		
		int icmd = cmd;
		buffer ~= cast(ubyte)icmd;
		int itype = fromNatType;
		buffer ~= cast(ubyte)itype;
		
		buffer ~= cast(ubyte)(from_buf.length);
		buffer ~= from_buf;
		buffer ~= cast(ubyte)(to_buf.length);
		buffer ~= to_buf;
		buffer ~= cast(ubyte)(data_buf.length);
		buffer ~= data_buf;
		buffer ~= strToByte_hex(MD5(buffer)[0..4]);

		return buffer;
	}

	static Nullable!Packet parse(ushort magicNumber, ubyte[] buffer)
	{
		assert(buffer.length >= 10);
		
		ushort t_magic, t_len, t_crc;
		t_magic = buffer.peek!ushort(0);
		t_len = buffer.peek!ushort(2);
		
		if ((t_magic != magicNumber) || (t_len > buffer.length - 4))
		{
			return Nullable!Packet();
		}
		
		buffer = buffer[0..t_len + 4];
		t_crc = buffer.peek!ushort(buffer.length - 2);
		
		if (strToByte_hex(MD5(buffer[0..$ - 2])[0..4]) != buffer[$ - 2..$])
		{
			return Nullable!Packet();
		}

		buffer = buffer[4..$ - 2];
		Packet packet;
		
		packet.cmd = cast(Cmd)(buffer[0]);
		packet.fromNatType = cast(NATType)(buffer[1]);
		buffer = buffer[2..$];
		
		t_len = buffer[0];
		packet.fromPeerId = cast(string)buffer[1..t_len + 1];
		buffer = buffer[1 + t_len..$];
		
		t_len = buffer[0];
		packet.toPeerId = cast(string)buffer[1..t_len + 1];
		buffer = buffer[1 + t_len..$];
		
		t_len = buffer[0];
		packet.data = buffer[1..$];

		return Nullable!Packet(packet);
	}
}