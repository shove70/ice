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

import ice.peer, ice.peerother, ice.utils, ice.stunserver, ice.iceclient, ice.natinfo, ice.packet;

/**
make hole scheme:

0 OpenInternet
1 FullCone
2 Restrict
3 RestrictPort
4 Symmetric

0:
	0: marked as hasHole
	1: request, response
	2: ditto
	3: ditto
	4: request, response, Save peer other's IP/Port
1:
	0: direct request, response
	1: request, response
	2: ditto
	3: ditto
	4: request, response, Save peer other's IP/Port
2:
	0: direct request, response
	1: request, response
	2: ditto
	3: ditto
	4: request, response, Save peer other's IP/Port
3:
	0: direct request, response
	1: request, response
	2: ditto
	3: ditto
	4: No handling, direct forwarding!!
4:
	0: direct request, response
	1: request, response, peer other save self's IP/Port
	2: ditto
	3: No handling, direct forwarding!!
	4: No handling, direct forwarding!!
*/

__gshared bool trackerConnected = false;
__gshared PeerOther[string] peers;

alias void delegate(string fromPeerId, string toPeerId, ubyte[] data, bool isForward) postMessageCallback;

private:

StunServer[] stunServerList;
__gshared string trackerHost;
__gshared ushort trackerPort;
__gshared ushort magicNumber;

__gshared UdpSocket socket;

void listener(shared PeerSelf _self, postMessageCallback dg)
{
	PeerSelf self = cast(PeerSelf)_self;

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
		
		//writefln("Received, cmd: %s, from: %s, to: %s, content: %s", packet.cmd, packet.fromPeerId, packet.toPeerId, cast(string)packet.data);
		handler(self, dg, packet, address);
    }
}

void handler(PeerSelf self, postMessageCallback dg, Packet packet, Address sourceAddress)
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
//					if (po.natInfo.natType != NATType.SymmetricNAT)
//						po.natInfo.externalPort = poNew.natInfo.externalPort;
				}
				else
				{
					peers[tp[0]] = poNew;
				}
			}
			break;
		case Cmd.PostMessageDirect:
			PeerOther po = new PeerOther(packet.fromPeerId, packet.fromNatType, sourceAddress);
			if (packet.fromPeerId !in peers)
			{
				peers[packet.fromPeerId] = po;
			}
			po = peers[packet.fromPeerId];
			po.hasHole = true;
			dg(packet.fromPeerId, packet.toPeerId, packet.data, false);
			break;
		case Cmd.PostMessageForward:
			dg(packet.fromPeerId, packet.toPeerId, packet.data, true);
			break;
		case Cmd.RequestMakeHoleDirect:
			PeerOther po = new PeerOther(packet.fromPeerId, packet.data);
			if (packet.fromPeerId !in peers)
			{
				peers[packet.fromPeerId] = po;
			}
			po = peers[packet.fromPeerId];
			po.hasHole = true;
			if (po.natInfo.natType == NATType.SymmetricNAT)
			{
				po.natInfo.externalIp = sourceAddress.toAddrString();
				po.natInfo.externalPort = sourceAddress.toPortString().to!ushort;
			}
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHoleDirect, self.natInfo.natType, self.peerId, packet.fromPeerId);
			Address address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
			for (int i = 0; i < 3; i++)
			{
				socket.sendTo(cast(ubyte[])buffer, address);
			}
			break;
		case Cmd.RequestMakeHoleForward:
			PeerOther po = new PeerOther(packet.fromPeerId, packet.data);
			if (packet.fromPeerId !in peers)
			{
				peers[packet.fromPeerId] = po;
			}
			po = peers[packet.fromPeerId];
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHoleForward, self.natInfo.natType, self.peerId, packet.fromPeerId);
			Address address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
			for (int i = 0; i < 3; i++)
			{
				socket.sendTo(cast(ubyte[])buffer, address);
			}
			address = new InternetAddress(trackerHost, trackerPort);
			socket.sendTo(buffer, address);
			break;
		case Cmd.ResponseMakeHoleDirect:
			PeerOther po = new PeerOther(packet.fromPeerId, packet.fromNatType, sourceAddress);
			if (packet.fromPeerId !in peers)
			{
				peers[packet.fromPeerId] = po;
			}
			po = peers[packet.fromPeerId];
			po.hasHole = true;
			if (po.natInfo.natType == NATType.SymmetricNAT)
			{
				po.natInfo.externalIp = sourceAddress.toAddrString();
				po.natInfo.externalPort = sourceAddress.toPortString().to!ushort;
			}
			break;
		case Cmd.ResponseMakeHoleForward:
			break;
		case Cmd.Heartbeat:
			break;
	}
}

void reportPeerInfoToServer(shared PeerSelf _self)
{
	writeln("Reported peer self's info to server.");
	
	PeerSelf self = cast(PeerSelf)_self;
	Address address = new InternetAddress(trackerHost, trackerPort);
	ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo, self.natInfo.natType, self.peerId, string.init);
	
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
	ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, self.natInfo.natType, self.peerId, string.init);
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
	ubyte[] buffer = Packet.build(magicNumber, Cmd.Heartbeat, self.natInfo.natType, string.init, string.init);	// minimize it.
	
	while (true)
	{
		Thread.sleep(10.seconds);
		
		Address address = new InternetAddress(trackerHost, trackerPort);
		socket.sendTo(buffer, address);
		
		if (self.isNatAllow)
		{
			foreach(PeerOther po; peers)
			{
				if (!po.hasHole)
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
			if (po.hasHole || !isNatAllow(po.natInfo.natType) || !canMakeHole(po.natInfo.natType))
			{
				continue;
			}
			
			if ((po.peerId == this.peerId) || ((this.natInfo.natType == NATType.OpenInternet) && (po.natInfo.natType == NATType.OpenInternet)))
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
		
		if ((po.peerId == this.peerId) || ((this.natInfo.natType == NATType.OpenInternet) && (po.natInfo.natType == NATType.OpenInternet)))
		{
			po.hasHole = true;
			return;
		}
		
		if (!isNatAllow(po.natInfo.natType))
		{
			if (consoleMessage) writeln("Peerother's NAT type not support.");
			return;
		}
		
		if (!canMakeHole(po.natInfo.natType))
		{
			if (consoleMessage) writeln("Both sides's NAT type not support.");
			return;
		}

		ubyte[] buffer;

		if (po.natInfo.natType != NATType.OpenInternet)
		{
			buffer = Packet.build(magicNumber, Cmd.RequestMakeHoleForward, this.natInfo.natType, this.peerId, po.peerId, cast(ubyte[])(this.serialize));
			socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
		}

		buffer = Packet.build(magicNumber, Cmd.RequestMakeHoleDirect, this.natInfo.natType, this.peerId, po.peerId, cast(ubyte[])(this.serialize));
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
			if ((po.peerId == this.peerId) || ((this.natInfo.natType == NATType.OpenInternet) && (po.natInfo.natType == NATType.OpenInternet)))
			{
				po.hasHole = true;
			}

			if ((po.peerId == this.peerId) || !isNatAllow(po.natInfo.natType))
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
		
		if (po.hasHole)
		{
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageDirect, this.natInfo.natType, this.peerId, toPeerId, data);
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
		}
		else if (!canMakeHole(po.natInfo.natType))
		{
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageForward, this.natInfo.natType, this.peerId, toPeerId, data);
			socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
		}
		else if (consoleMessage) writeln("Error: There is no connection to peer other yet.");
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

	private bool canMakeHole(NATType poNatType)
	{
		if (!isNatAllow)
			return false;
		
		if (this.natInfo.natType == NATType.RestrictPortNAT)
		{
			if (poNatType == NATType.SymmetricNAT)
				return false;
		}
		
		if (this.natInfo.natType == NATType.SymmetricNAT)
		{
			if ((poNatType == NATType.RestrictPortNAT) || (poNatType == NATType.SymmetricNAT))
				return false;
		}
		
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