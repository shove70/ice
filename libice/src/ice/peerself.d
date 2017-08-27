module ice.peerself;

import std.stdio;
import std.file;
import std.json;
import std.conv;
import std.array;
import std.socket;
import std.typecons;
import std.datetime;
import core.thread;
import std.concurrency;

import cryption.base58;

import ice.peer, ice.peerother, ice.utils, ice.stunserver, ice.iceclient, ice.nattype, ice.natinfo, ice.packet, ice.cmd;

__gshared bool trackerConnected = false;
__gshared PeerOther[string] peers;

alias void delegate(string fromPeerId, string toPeerId, ubyte[] data) postMessageCallback;

private:

StunServer[] stunServerList;
__gshared string trackerHost;
__gshared ushort trackerPort;
__gshared ushort magicNumber;

__gshared UdpSocket socket;

void listener(shared PeerSelf _self, postMessageCallback _dg)
{
	PeerSelf self = cast(PeerSelf)_self;
	postMessageCallback dg = cast(postMessageCallback)_dg;

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
		
		//writefln("Received, cmd:%s, from: %s, to: %s, content: %s", packet.cmd, packet.fromPeerId, packet.toPeerId, cast(string)packet.data);
		
		handler(self, dg, packet);
    }
}

void handler(PeerSelf self, postMessageCallback dg, Packet packet)
{
	final switch (packet.cmd)
	{
		case Cmd.ReportPeerInfo:
			trackerConnected = true;
			break;
		case Cmd.RequestAllPeers:
			string[] strs = (cast(string)(packet.data)).split(";");
			foreach(str; strs)
			{
				string[] tp = str.split("|");
				if (tp.length != 2) continue;
				
				PeerOther poNew = new PeerOther(tp[0], tp[1]);
				if (tp[0] in peers)
				{
					PeerOther po = peers[tp[0]];
					po.natInfo.externalIp = poNew.natInfo.externalIp;
					if (po.natInfo.natType != NATType.SymmetricNAT)
						po.natInfo.externalPort = poNew.natInfo.externalPort;
				}
				else
				{
					peers[tp[0]] = poNew;
				}
			}
			break;
		case Cmd.PostMessage:
			dg(packet.fromPeerId, packet.toPeerId, packet.data);
			//writefln("%s postMessage to %s: %s", packet.fromPeerId, packet.toPeerId, packet.data);
			break;
		case Cmd.RequestMakeHole:
			PeerOther po = new PeerOther(packet.fromPeerId, cast(string)(packet.data));
			if (packet.fromPeerId !in peers)
			{
				peers[packet.fromPeerId] = po;
			}
			po = peers[packet.fromPeerId];
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHole, self.peerId, packet.fromPeerId);
			if (!po.hasHole)
			{
				Address address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);

				for (int i = 0; i < 3; i++)
				{
					socket.sendTo(cast(ubyte[])buffer, address);
				}	
			}
			Address address = new InternetAddress(trackerHost, trackerPort);
			socket.sendTo(buffer, address);
			break;
		case Cmd.ResponseMakeHole:
		case Cmd.Heartbeat:
			if (packet.fromPeerId !in peers)
			{
				break;
			}
			peers[packet.fromPeerId].hasHole = true;
			break;
	}
}

void reportPeerInfoToServer(shared PeerSelf _self)
{
	writeln("Reported peer self's info to server.");
	
	PeerSelf self = cast(PeerSelf)_self;
	Address address = new InternetAddress(trackerHost, trackerPort);
	ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo, self.peerId, string.init, cast(ubyte[])self.serialize);
	
	int times = 1;
	while (!trackerConnected)
	{
		for (int i = 0; i < times; i++)
			socket.sendTo(buffer, address);
		
		times++;
		if (times > 3) times = 3;
		Thread.sleep(5.seconds);
	}
}

void getPeers(shared PeerSelf _self)
{
	PeerSelf self = cast(PeerSelf)_self;
	ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, self.peerId, string.init);
	Address address = new InternetAddress(trackerHost, trackerPort);
	
	while (true)
	{
		if (!trackerConnected)
		{
			Thread.sleep(5.seconds);
			
			continue;
		}
		
		socket.sendTo(buffer, address);
		Thread.sleep(1.minutes);
	}
}

void connectPeers(shared PeerSelf _self)
{
	PeerSelf self = cast(PeerSelf)_self;
	
	int times = 5000;
	while (true)
	{
		if (!self.autoConnectPeerOthers)
		{
			Thread.sleep(500.msecs);
			
			continue;
		}
		
		if (!trackerConnected)
		{
			Thread.sleep(5.seconds);
			
			continue;
		}
		
		self.connectToPeers(false);
		Thread.sleep(times.msecs);
		
		if (times < 60000) times += 5000;
	}
}

void heartbeat(shared PeerSelf _self)
{
	PeerSelf self = cast(PeerSelf)_self;
	ubyte[] buffer = Packet.build(magicNumber, Cmd.Heartbeat, self.peerId, string.init);
	
	while (true)
	{
		Thread.sleep(10.seconds);
		
		Address address = new InternetAddress(trackerHost, trackerPort);
		socket.sendTo(buffer, address);
		
		if (self.isNatAllow && self.natInfo.natType != NATType.SymmetricNAT)
		{
			foreach(PeerOther po; peers)
			{
				if (!po.hasHole || !self.isNatAllow(po.natInfo.natType) || (po.natInfo.natType == NATType.SymmetricNAT))
					continue;
					
				address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
				socket.sendTo(buffer, address);
			}
		}
	}
}

public:

final class PeerSelf : Peer
{
	bool autoConnectPeerOthers = false;
	
	this()
	{
		loadConfig();
		getPeerId();
		
		socket = new UdpSocket();
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
		socket.bind(new InternetAddress("0.0.0.0", 0));

		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(2));
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(2));
		getNatInfo();
		
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(5));
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(5));
		
		if (!isNatAllow(natInfo.natType))
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		spawn!()(&reportPeerInfoToServer, cast(shared PeerSelf)this);
	}
	
	public bool start(postMessageCallback dg)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return false;
		}
		
		writefln("Listening on %s:%d.", natInfo.localIp, natInfo.localPort);
		spawn!()(&listener,		cast(shared PeerSelf)this, cast(shared postMessageCallback)dg);
		
		spawn!()(&getPeers,		cast(shared PeerSelf)this);
		spawn!()(&connectPeers,	cast(shared PeerSelf)this);
		spawn!()(&heartbeat,	cast(shared PeerSelf)this);
		
		return true;
	}
	
	public void connectToPeers(bool consoleMessage = true)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		foreach(ref PeerOther po; peers)
		{
			if (po.hasHole || !isNatAllow(po.natInfo.natType))// || (po.natInfo.natType == NATType.SymmetricNAT))
			{
				continue;
			}
			
			if ((po.peerId == this.peerId) || (po.natInfo.natType == NATType.OpenInternet))
			{
				po.hasHole = true;
				continue;
			}
			
			connectToPeer(po, false);
		}
		
		if (consoleMessage) writeln("Consult to all peers to make a hole...");
	}
	
	public void connectToPeer(PeerOther po, bool consoleMessage = true)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		if (po.peerId == peerId)
		{
			po.hasHole = true;
			return;
		}
		
		ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestMakeHole, this.peerId, po.peerId, cast(ubyte[])serialize);
		socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
		
		Address address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
		
		for (int i = 0; i < 3; i++)
		{
			socket.sendTo(buffer, address);
		}
		
		if (consoleMessage) writefln("Consult to %s to make a hole...", peerId);
	}

	public void broadcastMessage(ubyte[] data)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		foreach(ref PeerOther po; peers)
		{
			if (po.natInfo.natType == NATType.OpenInternet)
			{
				po.hasHole = true;
			}

			if (!isNatAllow(po.natInfo.natType))
			{
				continue;
			}
			
			postMessage(po.peerId, data, false);
		}
	}

	public void postMessage(string toPeerId, ubyte[] data, bool consoleMessage = true)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		PeerOther po = peers[toPeerId];
		if (!isNatAllow(po.natInfo.natType))
		{
			if (consoleMessage) writefln("%s's NAT type not support.", toPeerId);
			return;
		}
		
		ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessage, peerId, toPeerId, data);
		if (po.hasHole || po.natInfo.natType == NATType.OpenInternet)
		{
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
			return;
		}

		if ((this.natInfo.natType == NATType.SymmetricNAT) || (po.natInfo.natType == NATType.SymmetricNAT))
		{
			socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
			return;
		}
		
		if (consoleMessage) writeln("Error: There is no connection to peer other yet.");
	}

	private string createPeerId()
	{
		string uuid = genUuid();

		return Base58.encode(cast(byte[])strToByte_hex(uuid ~ MD5(uuid)[0 .. 8]));
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
		writeln("PeerId: ", peerId);
	}

	private void getNatInfo()
	{
		natInfo.reset();
		IceClient client = new IceClient(socket, stunServerList);
		client.getNatInfo(&natInfo);
	}
	
	private bool isNatAllow()
	{
		return isNatAllow(natInfo.natType);
	}
	
	private bool isNatAllow(NATType nt)
	{
		int type = nt;
		if ((nt < 0) || (nt > 4)) return false;
		return true;
	}

	private void loadConfig()
	{
		JSONValue j = parseJSON(std.file.readText("./ice.conf"));
	
		foreach(element; j["stun_servers_list"].array)
		{
			stunServerList ~= StunServer(element["host"].str, element["port"].str.to!ushort);
		}
	
		JSONValue jt = j["tracker"];
		trackerHost = jt["host"].str;
		trackerPort = jt["port"].str.to!ushort;
		
		jt = j["protocol"];
		magicNumber = jt["magic number"].str.to!ushort;
	}
}