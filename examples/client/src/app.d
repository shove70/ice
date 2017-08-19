module app;

import std.stdio;
import std.json;
import std.file;
import std.conv;
import std.socket;
import std.bitmanip;
import std.typecons;
import std.string;
import std.array;
import std.datetime;
import core.thread;
import std.concurrency;

import ice;

import msgprotocol;

StunServer[] stunServerList;
string trackerHost;
ushort trackerPort;

string[string] peers;
__gshared Peer self;

void main()
{
	writeln("ice client.");
	loadConfig();
	
	self = new Peer();
	self.getNatInfo(stunServerList);
	
	writeln("peer id: ", self.peerId);
	writeln(self.natInfo);
	
	int selfNat = self.natInfo.natType;
	if ((selfNat < 0) || (selfNat > 4))
	{
		writeln("self's NAT type not support.");
		return;
	}
	
	reportPeerInfoToServer();
	getAllPeers();
	
	writefln("Listening on %s:%d.", self.natInfo.localIp, self.natInfo.localPort);
	spawn!()(&chatListener);

	showMenu();
	
	string line;
    while ((line = readln()) !is null)
	{
		line = line[0..$ - 1];		
		if (line == string.init)
			continue;
			
		if (line == "exit")
		{
			import core.stdc.stdlib;
			exit(0);
			return;
		}
				
		if (line == "peers")
		{
			getAllPeers();
			showMenu();
		    continue;
	    }
		
		say(line);
	}
}

void showMenu()
{
	writeln();
	writeln("All peers:");
	for(int i; i < peers.keys.length; i++)
	{
		writefln("%d: %s", i + 1, peers.keys[i]);
	}
	writeln("Menu:");
	writeln("1. press the \"peers\" to request all peers from server.");
	writeln("2. press other string will be send to all peers.");
	writeln("3. press \"exit\" to exit the client.");
	write("Please input: ");
}

void reportPeerInfoToServer()
{
	TcpSocket sock = createServerConnection();
	ubyte[] buffer = MsgProtocol.build(1, self.peerId, string.init, self.serialize());
	sock.send(buffer);
	buffer = receive(sock);
	sock.close();
	
	Nullable!Packet packet = MsgProtocol.parse(buffer);
	if (packet.isNull)
	{
		writeln("report peer info to server for self error.");
	}
	
	if (packet.content != string.init)
	{
		writeln(packet.content);
	}
}

void getAllPeers()
{
	TcpSocket sock = createServerConnection();
	ubyte[] buffer = MsgProtocol.build(2, self.peerId, string.init, string.init);
	sock.send(buffer);
	buffer = receive(sock);
	sock.close();
	
	Nullable!Packet packet = MsgProtocol.parse(buffer);
	if (packet.isNull)
	{
		writeln("request peers error.");
		
		return;
	}
	
	if (packet.content == string.init)
	{
		return;
	}
	
	string[] strs = packet.content.split(";");
	foreach(str; strs)
	{
		string[] tp = str.split("|");
		if (tp.length != 2) continue;
		
		peers[tp[0]] = tp[1];
		
		if (tp[0] != self.peerId)
		{
			consultMakeHole(tp[0], tp[1]);
		}
	}
}

void say(string sayString)
{
	int selfNat = self.natInfo.natType;
	if ((selfNat < 0) || (selfNat > 4))
	{
		writeln("self's NAT type not support.");
		return;
	}
	
	foreach(k, v; peers)
	{
		Peer peer = new Peer(k, v);
		int peerNat = peer.natInfo.natType;
		if ((peerNat < 0) || (peerNat > 4))
		{
			continue;
		}
		
		ubyte[] buffer = MsgProtocol.build(3, self.peerId, peer.peerId, sayString);
		
		if ((selfNat == 4) || (peerNat == 4))
		{
			TcpSocket sock = createServerConnection();
			sock.send(buffer);
			buffer = receive(sock);
			sock.close();
			sock = null;
		}
		else
		{
			UdpSocket sock = createToPeerConnection();
			sock.sendTo(buffer, new InternetAddress(peer.natInfo.externalIp, peer.natInfo.externalPort));
			//sock.sendTo(buffer, new InternetAddress(self.natInfo.localIp, self.natInfo.localPort));
			sock.close();
			sock = null;
		}
	}
	
	//writeln("ok, sent to all peers success.");
}

private void consultMakeHole(string peerId, string peerSerializedString)
{
	Peer peer = new Peer(peerId, peerSerializedString);
	UdpSocket sock = createToPeerConnection();
	ubyte[] buffer = MsgProtocol.build(4, self.peerId, peer.peerId, string.init);
	sock.sendTo(buffer, new InternetAddress(peer.natInfo.externalIp, peer.natInfo.externalPort));
	//sock.sendTo(buffer, new InternetAddress(self.natInfo.localIp, self.natInfo.localPort));
	sock.close();
	sock = null;
}

private TcpSocket createServerConnection()
{
	TcpSocket sock = new TcpSocket();
	sock.bind(new InternetAddress("0.0.0.0", 0));
	sock.connect(new InternetAddress(trackerHost, trackerPort));
	
	return sock;
}

private UdpSocket createToPeerConnection()
{
	UdpSocket sock = new UdpSocket();
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
	sock.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(5));
	sock.bind(new InternetAddress(self.natInfo.localIp, self.natInfo.localPort));//"0.0.0.0", 0));
	
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

void chatListener()
{
	auto listener = new UdpSocket();
	listener.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    listener.bind(new InternetAddress(self.natInfo.localIp, self.natInfo.localPort));
    
    while (true)
    {
    	Address address = new InternetAddress(InternetAddress.ADDR_ANY, InternetAddress.PORT_ANY);
    	
	    ubyte[] buffer = new ubyte[10240];
    	listener.receiveFrom(buffer, address);
    	
    	ubyte[] head = buffer[0..4];
		int msgLength = head.peek!int();
	    buffer = buffer[4..4 + msgLength];
    	
    	Nullable!Packet packet = MsgProtocol.parse(buffer);
	
		if (packet.isNull)
		{
			continue;
		}
		
		switch (packet.cmd)
		{
			case 3:
				writefln("%s say to %s: %s", packet.fromPeerId, packet.toPeerId, packet.content);
				break;
			default:
				break;
		}
    }
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