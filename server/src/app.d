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

private void handler(Packet packet, Address sourceAddress)
{
	PeerOther fromPeer = new PeerOther(packet.fromPeerId, packet.fromNatType, sourceAddress);
	peers[packet.fromPeerId] = fromPeer;
	
	final switch (packet.cmd)
	{
		case Cmd.ReportPeerInfo:
			//PeerOther po = new PeerOther(packet.fromPeerId, packet.fromNatType, sourceAddress);
			//peers[packet.fromPeerId] = po;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo, NATType.Uninit, string.init, packet.fromPeerId);
			socket.sendTo(buffer, sourceAddress);
			break;
		case Cmd.RequestAllPeers:
			string response;
			foreach(k, v; peers)
			{
				//if (k == packet.fromPeerId) continue;
				response ~= (k ~ "|" ~ v.serialize ~ ";");
			}
			if (response == string.init) response = ";";
			ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, NATType.Uninit, string.init, packet.fromPeerId, cast(ubyte[])(response[0..$ - 1]));
			socket.sendTo(buffer, sourceAddress);
			break;
		case Cmd.PostMessageDirect:
		case Cmd.PostMessageForward:
			if (packet.toPeerId !in peers) return;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageForward, packet.fromNatType, packet.fromPeerId, packet.toPeerId, packet.data);
			PeerOther po = peers[packet.toPeerId];
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			break;
		case Cmd.RequestMakeHoleDirect:
		case Cmd.RequestMakeHoleForward:
			if (packet.toPeerId !in peers) return;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestMakeHoleForward, packet.fromNatType, packet.fromPeerId, packet.toPeerId, packet.data);
			PeerOther po = peers[packet.toPeerId];
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			break;
		case Cmd.ResponseMakeHoleDirect:
		case Cmd.ResponseMakeHoleForward:
			if (packet.toPeerId !in peers) return;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHoleForward, NATType.Uninit, packet.fromPeerId, packet.toPeerId);
			PeerOther po = peers[packet.toPeerId];
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			break;
		case Cmd.Heartbeat:
			ubyte[] buffer = Packet.build(magicNumber, Cmd.Heartbeat, NATType.Uninit, string.init, string.init);	// minimize it.
			socket.sendTo(buffer, sourceAddress);
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
