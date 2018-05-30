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

import crypto.base58;

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

alias void delegate(string fromPeerId, ubyte[] data, bool isForward) PostMessageCallback;

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
	
	PeerOther parseSender()
	{
		if (packet.senderPeerId == string.init)
		{
			return null;
		}
		
		PeerOther po;
		
		if (packet.senderPeerId !in peers)
		{
			peers[packet.senderPeerId] = new PeerOther(packet.senderPeerId, packet.senderNatType, address);
			po = peers[packet.senderPeerId];
		}
		else
		{
			po = peers[packet.senderPeerId];
			po.natInfo.natType = packet.senderNatType;
			po.natInfo.externalIp = address.toAddrString();
			po.natInfo.externalPort = address.toPortString().to!ushort;
		}

		po.lastHeartbeat = ice.utils.currTimeTick;
		
		return po;
	}

	PeerOther parseAdditionalPo()
	{
		if (packet.additionalPo is null)
		{
			return null;
		}
		
		PeerOther po;
		
		if (packet.additionalPo.peerId !in peers)
		{
			peers[packet.additionalPo.peerId] = packet.additionalPo;
			po = peers[packet.additionalPo.peerId];
		}
		else
		{
			po = peers[packet.additionalPo.peerId];
			//po.natInfo.natType = packet.senderNatType;		// The sender cannot be trusted with the latest results
			//po.natInfo.externalIp = address.toAddrString();
			//po.natInfo.externalPort = address.toPortString().to!ushort;		
		}
		
		return po;
	}

	final switch (packet.cmd)
	{
		case Cmd.ReportPeerInfo:
			trackerConnected = true;
			break;
		case Cmd.RequestAllPeers:
			ubyte[] response = packet.data;
			
			while (response.length > 0)
			{
				int len = response[0];
				ubyte[] serialized = response[1..len + 1];
				PeerOther poNew = new PeerOther(serialized);
				if (poNew.peerId in peers)
				{
					PeerOther po = peers[poNew.peerId];
					po.natInfo.natType = poNew.natInfo.natType;
					po.natInfo.externalIp = poNew.natInfo.externalIp;
					if (po.natInfo.natType != NATType.SymmetricNAT)
						po.natInfo.externalPort = poNew.natInfo.externalPort;
				}
				else
				{
					peers[poNew.peerId] = poNew;
				}
				response = response[len + 1..$];
			}
			
			break;
		case Cmd.PostMessageDirect:
			PeerOther po = parseSender();
			if (po is null)		break;
			po.hasHole = true;
			dg(packet.senderPeerId, packet.data, false);
			break;
		case Cmd.PostMessageForward:
			PeerOther additionalPo = parseAdditionalPo();
			if (additionalPo is null)	break;
			dg(additionalPo.peerId, packet.data, true);
			break;
		case Cmd.RequestMakeHoleDirect:
			PeerOther po = parseSender();
			if (po is null)		break;
			po.hasHole = true;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHole, self.natInfo.natType, self.peerId);
			Address addr = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
			for (int i = 0; i < 3; i++)
			{
				socket.sendTo(cast(ubyte[])buffer, addr);
			}
			break;
		case Cmd.RequestMakeHoleForward:
			PeerOther additionalPo = parseAdditionalPo();
			if (additionalPo is null)	break;
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHole, self.natInfo.natType, self.peerId);
			if (!additionalPo.hasHole && !additionalPo.consulting)
			{
				SysTime time1 = Clock.currTime();
				Address addr = new InternetAddress(additionalPo.natInfo.externalIp, additionalPo.natInfo.externalPort);
				additionalPo.consulting = true;
				
				while (!additionalPo.hasHole)
				{
					socket.sendTo(buffer, addr);
					
					SysTime time2 = Clock.currTime();
					if ((time2 - time1).total!"seconds" > 30)	break;
				}
				
				additionalPo.consulting = false;
			}
			break;
		case Cmd.ResponseMakeHole:
			PeerOther po = parseSender();
			if (po is null)		break;
			po.hasHole = true;
			break;
		case Cmd.Heartbeat:
			if (packet.senderPeerId != string.init)
			{
				PeerOther po = parseSender();
				if (po is null)		break;
				po.hasHole = true;
				po.lastHeartbeat = ice.utils.currTimeTick;
			}
			break;
	}
}

void reportPeerInfoToServer(shared PeerSelf _self)
{
	writeln("Reported peer self's info to server.");
	
	PeerSelf self = cast(PeerSelf)_self;
	Address address = new InternetAddress(trackerHost, trackerPort);
	ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo, self.natInfo.natType, self.peerId);
	
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
	ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, self.natInfo.natType, self.peerId);
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
		
		self.connectPeers(false);
		Thread.sleep(times.msecs);
		
		if (times < 60000) times += 5000;
	}
}

void heartbeat(shared PeerSelf _self)
{
	PeerSelf self = cast(PeerSelf)_self;
	ubyte[] buffer1 = Packet.build(magicNumber);	// minimize it.
	ubyte[] buffer2 = Packet.build(magicNumber, Cmd.Heartbeat, self.natInfo.natType, self.peerId);
	
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

void savePeers(shared PeerSelf _self)
{
	PeerSelf self = cast(PeerSelf)_self;

	while (true)
	{
		Thread.sleep(10.minutes);

		self.savePeers();
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
		
		loadPeers();

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
		spawn!()(&listener,						cast(shared PeerSelf)this, cast(shared PostMessageCallback)dg);
		
		spawn!()(&getPeers,						cast(shared PeerSelf)this);
		spawn!()(&ice.peerself.connectPeers,	cast(shared PeerSelf)this);
		spawn!()(&heartbeat,					cast(shared PeerSelf)this);
		spawn!()(&ice.peerself.savePeers,		cast(shared PeerSelf)this);
		
		return true;
	}
	
	public void connectPeers(bool consoleMessage = true)
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
			
			connectPeer(po, false);
		}
		
		if (consoleMessage) writeln("Consult to all peers to make a hole...");
	}
	
	public void connectPeer(PeerOther po, bool consoleMessage = true)
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
			buffer = Packet.build(magicNumber, Cmd.RequestMakeHoleForward, this.natInfo.natType, this.peerId, po);
			socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
		}

		buffer = Packet.build(magicNumber, Cmd.RequestMakeHoleDirect, this.natInfo.natType, this.peerId);
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
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageDirect, this.natInfo.natType, this.peerId, null, data);
			socket.sendTo(buffer, new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort));
		}
		else if (!po.natInfo.canMakeHole(this.natInfo))
		{
			ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageForward, this.natInfo.natType, this.peerId, po, data);
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

	private void loadPeers()
	{
		string path = "./.caches";
		string fileName = "./.caches/.peers";
			
		if (!std.file.exists(path))
		{
			try
			{
				std.file.mkdirRecurse(path);
			}
			catch (Exception e) { }
		}
		
		if (!std.file.exists(fileName))
		{
			return;
		}
	
		peers.clear;
		JSONValue json = parseJSON(cast(string)std.file.readText(fileName));
		
		foreach(JSONValue j; json.array)
		{
			PeerOther po			= new PeerOther(j["id"].str);
			po.natInfo.natType		= cast(NATType)(cast(int)(j["t"].integer));
			po.natInfo.externalIp	= j["ei"].str;
			po.natInfo.externalPort	= cast(ushort)(j["ep"].integer);
			po.natInfo.localIp		= j["li"].str;
			po.natInfo.localPort	= cast(ushort)(j["lp"].integer);
			po.discoveryTime		= j["dt"].integer;
			po.lastHeartbeat		= j["ht"].integer;
			po.tryConnectTimes		= cast(int)(j["tt"].integer);
			
			peers[po.peerId]		= po;
		}
	}

	public void savePeers()
	{
		string path = "./.caches";
		string fileName = "./.caches/.peers";
		
		if (!std.file.exists(path))
		{
			try
			{
				std.file.mkdirRecurse(path);
			}
			catch (Exception e) { }
		}
		
		JSONValue json = [null];
		json.array.length = 0;
		
		foreach(PeerOther po; peers)
		{
			JSONValue j = ["id": "", "t": "0", "ei": "", "ep": "0", "li": "", "lp": "0", "dt": "0", "ht": "0", "tt": "0"];
			j["id"].str		= po.peerId;
			int type		= po.natInfo.natType;
			j["t"].integer	= type;
			j["ei"].str		= po.natInfo.externalIp;
			j["ep"].integer	= po.natInfo.externalPort;
			j["li"].str		= po.natInfo.localIp;
			j["lp"].integer	= po.natInfo.localPort;
			j["dt"].integer	= po.discoveryTime;
			j["ht"].integer	= po.lastHeartbeat;
			j["tt"].integer	= po.tryConnectTimes;
			json.array ~= j;
		}
	
		std.file.write(fileName, cast(byte[])json.toString());
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