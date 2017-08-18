module app;

import std.stdio;
import std.json;
import std.file;
import std.conv;
import std.socket;
import std.bitmanip;
import std.typecons;

import ice;

import msgprotocol;

StunServer[] stunServerList;
string trackerHost;
ushort trackerPort;

string[string] peers;
Peer self;

void main()
{
	writeln("ice client.");
	loadConfig();
	
	self = new Peer();
	self.getNatInfo(stunServerList);
	
	writeln("peer id: ", self.peerId);
	writeln(self.natInfo);
	
	reportPeerInfoForSelf();
}

void reportPeerInfoForSelf()
{
	TcpSocket sock = createServerConnection();
	ubyte[] buffer = MsgProtocol.build(1, self.peerId, string.init, self.serialize());
	sock.send(buffer);
	buffer = receive(sock);
	sock.close();
	
	Nullable!Packet packet = MsgProtocol.parse(buffer);
	if (packet.isNull)
	{
		writeln("error.");
	}
	
	if (packet.content == string.init)
	{
		writeln("ok.");
	}
	else
	{
		writeln(packet.content);
	}
}

private TcpSocket createServerConnection()
{
	TcpSocket sock = new TcpSocket();
	sock.bind(new InternetAddress("0.0.0.0", 0));
	sock.connect(new InternetAddress(trackerHost, trackerPort));
	
	return sock;
}

private ubyte[] receive(Socket sock)
{
	ubyte[] head = new ubyte[4];
	long len = sock.receive(head);
	
	if (len != 4)
	{
		return null;
	}
	
	int msgLength = head.peek!int();
    ubyte[] buffer = new ubyte[msgLength];
    len = sock.receive(buffer);

    if (len == Socket.ERROR)
    {
		return null;
	}

	return buffer;
}

private void loadConfig()
{
	JSONValue j = parseJSON(std.file.readText("./ice_client.conf"));

	foreach(element; j["stun_servers_list"].array)
	{
		stunServerList ~= StunServer(element["host"].str, element["port"].str.to!ushort);
	}

	JSONValue jt = j["tracker"];
	trackerHost = jt["host"].str;
	trackerPort = jt["port"].str.to!ushort;
}