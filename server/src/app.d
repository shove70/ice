module app;

import std.stdio;
import std.conv;
import std.json;
import std.file;
import core.thread;
import std.concurrency;
import std.socket;
import std.bitmanip;
import std.typecons;

import ice.all;

string host;
ushort port;
__gshared ushort magicNumber;

__gshared PeerOther[string] peers;
__gshared UdpSocket socket;

void main()
{
    writeln("ice server.");
    loadConfig();

	startListen();
}

void startListen()
{
	socket = new UdpSocket();
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(5));
	socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(5));
	socket.bind(new InternetAddress(host, port));
    
    writefln("Listening on port %d.", port);
	spawn!()(&listener);
}

void listener()
{
    while (true)
    {
    	Address address = new InternetAddress(InternetAddress.ADDR_ANY, InternetAddress.PORT_ANY);
    	
	    ubyte[] buffer = new ubyte[65507];
    	socket.receiveFrom(buffer, address);	    	
    	Nullable!Packet packet = Packet.parse(magicNumber, buffer);
	
		if (packet.isNull)
		{
			continue;
		}
		
		handler(packet, address);
    }
}

private void handler(Packet packet, Address address)
{
	writefln("Received, cmd:%d, from: %s, to: %s, content: %s", packet.cmd, packet.fromPeerId, packet.toPeerId, packet.data);
	
	final switch (packet.cmd)
	{
		case Cmd.ReportPeerInfo:
			peers[packet.fromPeerId] = new PeerOther(packet.fromPeerId, cast(string)packet.data);
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo, string.init, packet.fromPeerId);
			socket.sendTo(buffer, address);
			break;
		case Cmd.RequestAllPeers:
			string response;
			foreach(k, v; peers)
			{
				//if (k == packet.fromPeerId) continue;
				response ~= (k ~ "|" ~ v.serialize ~ ";");
			}
			if (response == string.init) response = ";";
			ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, string.init, packet.fromPeerId, cast(ubyte[])(response[0..$ - 1]));
			socket.sendTo(buffer, address);
			break;
		case Cmd.PostMessage:
			if (packet.toPeerId !in peers) return;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessage, packet.fromPeerId, packet.fromPeerId, packet.data);
			PeerOther po = peers[packet.toPeerId];
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			break;
		case Cmd.RequestMakeHole:
			if (packet.toPeerId !in peers) return;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestMakeHole, packet.fromPeerId, packet.fromPeerId, packet.data);
			PeerOther po = peers[packet.toPeerId];
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			break;
		case Cmd.ResponseMakeHole:
			if (packet.toPeerId !in peers) return;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHole, packet.fromPeerId, packet.fromPeerId, packet.data);
			PeerOther po = peers[packet.toPeerId];
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			break;
	}
}

private void loadConfig()
{
    JSONValue j = parseJSON(std.file.readText("./ice_tracker.conf"));

    JSONValue jt = j["tracker"];
    host = jt["host"].str;
    port = jt["port"].str.to!ushort;
    
    jt = j["protocol"];
	magicNumber = jt["magic number"].str.to!ushort;
}
