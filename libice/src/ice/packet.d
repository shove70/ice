module ice.packet;

import std.stdio;
import std.bitmanip;
import std.array;
import std.string;
import std.conv;
import std.typecons;

import ice.cmd, ice.utils;

/**
protocol rule (TLV):
	magic_number(ushort) ~ total_len(ushort) ~ cmd(byte) ~ len(byte)+from(string) ~ len(byte)+to(string) ~ len(ushort)+content(string) ~ ushort(hash(all)[0..4])
	
	cmd:
	
	01: report a peer info (for client self)	-> server reply: 01,"",to,""
	02: request all peers info from server.		-> server reply: 02,"",to,"id|info;id|info;..."
	03: postmessage(send/forward)				-> server forward to other peer
	04: request make hole						-> server -> other peer: 04 -> other peer reply(two):	-> peer: 05
																										-> server: 05 -> server to peer: 05
	05: response make hole						-> none
	06: heartbeat								-> none
*/

struct Packet
{
	Cmd cmd;
	string fromPeerId;
	string toPeerId;
	ubyte[] data;
	
	static ubyte[] build(ushort magicNumber, Cmd cmd, string fromPeerId, string toPeerId, ubyte[] data = null)
	{
		ubyte[] from_buf = cast(ubyte[])fromPeerId;
		ubyte[] to_buf = cast(ubyte[])toPeerId;
		ubyte[] data_buf = cast(ubyte[])data;
		ulong total_len = from_buf.length + to_buf.length + data_buf.length + 6;
		
		assert(total_len <= 65503);
		
		ubyte[] buffer = new ubyte[4];
		buffer.write!ushort(magicNumber, 0);
		buffer.write!ushort(cast(ushort)total_len, 2);
		
		int icmd = cmd;
		buffer ~= cast(ubyte)icmd;
		
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
		buffer = buffer[1..$];
		
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