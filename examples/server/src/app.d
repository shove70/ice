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

import ice;

import msgprotocol;

string host;
ushort port;

__gshared string[string] peers;

void main()
{
    writeln("ice server.");
    loadConfig();

	start();
}

void start()
{
	auto listener = new TcpSocket();
    listener.bind(new InternetAddress(host, port));
    listener.listen(10);
    writefln("Listening on port %d.", port);

    while (true)
    {
        Socket sock = listener.accept();
        spawn!()(&handler, cast(shared Socket)sock);
    }
}

void handler(shared Socket socket)
{
	Socket sock = cast(Socket)socket;
	
	ubyte[] head = new ubyte[4];
	long len = sock.receive(head);
	
	if (len != 4)
	{
		sock.close();
		writeln("Connection error.");
		return;
	}
	
	int msgLength = head.peek!int();
    ubyte[] buffer = new ubyte[msgLength];
    len = sock.receive(buffer);

    if (len == Socket.ERROR)
    {
		sock.close();
		writeln("Connection error.");
		return;
	}

	//writefln("Received %d bytes from %s: \"%s\"", len, sock.remoteAddress().toString(), buffer);
	buffer = doBusinessHandle(buffer);
	
	if (buffer !is null) sock.send(buffer);
    sock.close();
}

private ubyte[] doBusinessHandle(ubyte[] buffer)
{
	Nullable!Packet packet = MsgProtocol.parse(buffer);
	
	if (packet.isNull)
	{
		return null;
	}
	
	writefln("Received, cmd:%d, from: %s, to: %s, content: %s", packet.cmd, packet.fromPeerId, packet.toPeerId, packet.content);
	
	switch (packet.cmd)
	{
		case 1:
			peers[packet.fromPeerId] = packet.content;
			return MsgProtocol.build(packet.cmd, string.init, packet.fromPeerId, string.init);
		case 2:
			string response;
			foreach(k, v; peers)
			{
				response ~= (k ~ "," ~ v ~ ";");
			}
			if (response == string.init) response = ";";
			return MsgProtocol.build(packet.cmd, string.init, packet.fromPeerId, response[0..$ - 1]);
		case 3:
			if (packet.toPeerId !in peers)
			{
				return MsgProtocol.build(packet.cmd, string.init, packet.fromPeerId, "peer not found.");
			}
			Peer peer = new Peer(packet.toPeerId, peers[packet.toPeerId]);
			UdpSocket sock = new UdpSocket();
			sock.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(5));
			sock.bind(new InternetAddress("0.0.0.0", 0));
			sock.sendTo(buffer, new InternetAddress(peer.natInfo.externalIp, peer.natInfo.externalPort));
			sock.close();
			return MsgProtocol.build(packet.cmd, string.init, packet.fromPeerId, string.init);
		default:
			return MsgProtocol.build(packet.cmd, string.init, packet.fromPeerId, string.init);
	}
}

private void loadConfig()
{
    JSONValue j = parseJSON(std.file.readText("./ice_tracker.conf"));

    JSONValue jt = j["tracker"];
    host = jt["host"].str;
    port = jt["port"].str.to!ushort;
}
