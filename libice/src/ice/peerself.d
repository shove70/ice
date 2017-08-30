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

alias void delegate(string fromPeerId, string toPeerId, ubyte[] data, bool isForward) PostMessageCallback;

private:

StunServer[] stunServerList;
__gshared string trackerHost;
__gshared ushort trackerPort;
__gshared ushort magicNumber;

__gshared UdpSocket socket;

void listener(shared PeerSelf _self, shared PostMessageCallback dg)
{
    while (true)
    {
    	Address address = new InternetAddress(InternetAddress.ADDR_ANY, InternetAddress.PORT_ANY);
    	
	    ubyte[] buffer = new ubyte[65507];
    	socket.receiveFrom(buffer, address);
    	spawn!()(&handler, _self, dg, cast(shared ubyte[])buffer, cast(shared Address)address);
    }
}

void handler(shared PeerSelf _self, shared PostMessageCallback dg, shared ubyte[] _receiveData, shared Address _address)
{
	PeerSelf self		= cast(PeerSelf)	_self;
	ubyte[] receiveData	= cast(ubyte[])		_receiveData;
	Address address		= cast(Address)		_address;
	
	Nullable!Packet packet = Packet.parse(magicNumber, receiveData);

	if (packet.isNull)
	{
		return;
	}
	
	PeerOther parsePeerOther(Packet packet, Address address = null)
	{
		PeerOther po = (address is null)
						?
						new PeerOther(packet.fromPeerId, packet.data)
						:
						new PeerOther(packet.fromPeerId, packet.fromNatType, address);
		if (packet.fromPeerId !in peers)
		{
			peers[packet.fromPeerId] = po;
		}
		po = peers[packet.fromPeerId];
		return po;
	}

	void updateNatInfoForSymmetric(PeerOther po)
	{
		if (po.natInfo.natType == NATType.SymmetricNAT)
		{
			po.natInfo.externalIp = address.toAddrString();
			po.natInfo.externalPort = address.toPortString().to!ushort;
		}
	}

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
					po.natInfo.natType = poNew.natInfo.natType;
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
		case Cmd.PostMessageDirect:
			PeerOther po = parsePeerOther(packet, address);
			po.hasHole = true;
			dg(packet.fromPeerId, packet.toPeerId, packet.data, false);
			break;
		case Cmd.PostMessageForward:
			dg(packet.fromPeerId, packet.toPeerId, packet.data, true);
			break;
		case Cmd.RequestMakeHoleDirect:
			PeerOther po = parsePeerOther(packet);
			po.hasHole = true;
			updateNatInfoForSymmetric(po);
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHoleDirect, self.natInfo.natType, self.peerId, packet.fromPeerId);
			Address addr = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
			for (int i = 0; i < 3; i++)
			{
				socket.sendTo(cast(ubyte[])buffer, addr);
			}
			break;
		case Cmd.RequestMakeHoleForward:
			PeerOther po = parsePeerOther(packet);
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHoleForward, self.natInfo.natType, self.peerId, packet.fromPeerId);
			if (!po.hasHole && !po.consulting)
			{
				spawn!()(&consulting, packet.fromPeerId, cast(shared PeerOther)po, cast(shared ubyte[])buffer);
			}
			socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
			break;
		case Cmd.ResponseMakeHoleDirect:
			PeerOther po = parsePeerOther(packet, address);
			po.hasHole = true;
			updateNatInfoForSymmetric(po);
			break;
		case Cmd.ResponseMakeHoleForward:
			break;
		case Cmd.Heartbeat:
			if (packet.fromPeerId != string.init)
			{
				PeerOther po = parsePeerOther(packet);
				po.hasHole = true;
				updateNatInfoForSymmetric(po);
				po.lastHeartbeat = cast(DateTime)Clock.currTime();
			}
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

		if (times < 3) times++;
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

void consulting(string toPeerId, shared PeerOther po, shared ubyte[] buffer)
{
	if (po.hasHole || po.consulting)
		return;

	SysTime time1 = Clock.currTime();
	Address address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);

	po.consulting = true;
	
	while (!peers[toPeerId].hasHole)
	{
		socket.sendTo(cast(ubyte[])buffer, address);
		
		SysTime time2 = Clock.currTime();
		if ((time2 - time1).total!"seconds" > 30)
		{
			break;
		}
	}
	
	po.consulting = false;
}

void heartbeat(shared PeerSelf _self)
{
	PeerSelf self = cast(PeerSelf)_self;
	ubyte[] buffer1 = Packet.build(magicNumber, Cmd.Heartbeat, self.natInfo.natType, string.init, string.init);	// minimize it.
	ubyte[] buffer2 = Packet.build(magicNumber, Cmd.Heartbeat, self.natInfo.natType, self.peerId, string.init);	// minimize it.
	
	int count = 0;
	while (true)
	{
		Thread.sleep(10.seconds);
		
		Address address = new InternetAddress(trackerHost, trackerPort);
		socket.sendTo((count == 59) ? buffer2 : buffer1, address);
		
		if (self.natInfo.natUsable)
		{
			foreach(PeerOther po; peers)
			{
				if (!po.hasHole)
					continue;
					
				address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
				socket.sendTo((count == 59) ? buffer2 : buffer1, address);
			}
		}
		
		count++;
		count %= 60;
	}
}

public:

final class PeerSelf : Peer
{
	bool autoConnectPeerOthers = false;
	private bool cachePeerId = true;
	
	this(bool cachePeerId = true)
	{
		this.cachePeerId = cachePeerId;
		
		loadConfig();
		
		if (cachePeerId)
			getPeerId();
		else
			peerId = createPeerId();
		
		socket = new UdpSocket();
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
		socket.bind(new InternetAddress("0.0.0.0", 0));

		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(2));
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(2));
		
		getNatInfo();

		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(30));
		socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(30));
		
		if (!this.natInfo.natUsable)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		spawn!()(&reportPeerInfoToServer, cast(shared PeerSelf)this);
	}
	
	public bool start(PostMessageCallback dg)
	{
		if (!this.natInfo.natUsable)
		{
			writeln("Self's NAT type not support.");
			return false;
		}
		
		writefln("Listening on %s:%d.", natInfo.localIp, natInfo.localPort);
		spawn!()(&listener,		cast(shared PeerSelf)this, cast(shared PostMessageCallback)dg);
		
		spawn!()(&getPeers,		cast(shared PeerSelf)this);
		spawn!()(&connectPeers,	cast(shared PeerSelf)this);
		spawn!()(&heartbeat,	cast(shared PeerSelf)this);
		
		return true;
	}
	
	public void connectToPeers(bool consoleMessage = true)
	{
		if (!this.natInfo.natUsable)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		foreach(ref PeerOther po; peers)
		{
			if (po.hasHole || !po.natInfo.natUsable || !po.natInfo.canMakeHole(this.natInfo))
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
		if (!this.natInfo.natUsable)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		if ((po.peerId == this.peerId) || ((this.natInfo.natType == NATType.OpenInternet) && (po.natInfo.natType == NATType.OpenInternet)))
		{
			po.hasHole = true;
			return;
		}
		
		if (!po.natInfo.natUsable)
		{
			if (consoleMessage) writeln("Peerother's NAT type not support.");
			return;
		}
		
		if (!po.natInfo.canMakeHole(this.natInfo))
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
		
		po.tryConnectTimes++;
		
		if (consoleMessage) writefln("Consult to %s to make a hole...", peerId);
	}

	public void broadcastMessage(ubyte[] data)
	{
		if (!this.natInfo.natUsable)
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

			if ((po.peerId == this.peerId) || !po.natInfo.natUsable)
			{
				continue;
			}
			
			postMessage(po.peerId, data, false);
		}
	}

	public void postMessage(string toPeerId, ubyte[] data, bool consoleMessage = true)
	{
		if (!this.natInfo.natUsable)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		PeerOther po = peers[toPeerId];
		if (!po.natInfo.natUsable)
		{
			if (consoleMessage) writefln("%s's NAT type not support.", toPeerId);
			return;
		}
		
		if (po.hasHole)
		{
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageDirect, this.natInfo.natType, this.peerId, toPeerId, data);
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
		}
		else if (!po.natInfo.canMakeHole(this.natInfo))
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