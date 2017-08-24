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

package
{
	StunServer[] stunServerList;
	__gshared string trackerHost;
	__gshared ushort trackerPort;
	__gshared ushort magicNumber;
	
	__gshared UdpSocket socket;
}

__gshared bool trackerConnected = false;
__gshared PeerOther[string] peers;

alias void delegate(string fromPeerId, string toPeerId, ubyte[] data) postMessageCallback;

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
				
				peers[tp[0]] = new PeerOther(tp[0], tp[1]);
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
			ubyte[] buffer = Packet.build(magicNumber, Cmd.ResponseMakeHole, self.peerId, packet.fromPeerId);
			Address address = new InternetAddress(po.natInfo.externalIp, po.natInfo.externalPort);
			socket.sendTo(buffer, address);
			address = new InternetAddress(trackerHost, trackerPort);
			socket.sendTo(buffer, address);
			break;
		case Cmd.ResponseMakeHole:
			if (packet.fromPeerId !in peers)
			{
				break;
			}
			peers[packet.fromPeerId].hasHole = true;
			break;
	}
}

final class PeerSelf : Peer
{
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
		
		reportPeerInfoToServer();
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
		IceClient client = new IceClient(socket, stunServerList, &natInfo);
	}
	
	public bool isNatAllow()
	{
		return isNatAllow(natInfo.natType);
	}
	
	private bool isNatAllow(NATType nt)
	{
		int type = nt;
		if ((nt < 0) || (nt > 4)) return false;
		return true;
	}
	
	private void reportPeerInfoToServer()
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		Address address = new InternetAddress(trackerHost, trackerPort);
		
		ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo, peerId, string.init, cast(ubyte[])serialize);
		socket.sendTo(buffer, address);
		writeln("Reported peer self's info to server.");
	}
	
	public bool startListen(postMessageCallback dg)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return false;
		}
		
		writefln("Listening on %s:%d.", natInfo.localIp, natInfo.localPort);
		spawn!()(&listener, cast(shared PeerSelf)this, cast(shared postMessageCallback)dg);
		
		return true;
	}
	
	public void connectPeers()
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		foreach(ref PeerOther po; peers)
		{
			if (po.hasHole || !isNatAllow(po.natInfo.natType))
			{
				continue;
			}
			
			if ((po.peerId == this.peerId) || (po.natInfo.natType == NATType.OpenInternet))
			{
				po.hasHole = true;
				continue;
			}
			
			connectPeer(po.peerId, false);
		}
		
		writeln("Consult to all peers to make a hole...");
	}
	
	public void connectPeer(string peerOtherId, bool consoleMessage = true)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		if (peerOtherId == peerId) return;
		
		ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestMakeHole, this.peerId, peerOtherId, cast(ubyte[])serialize);
		socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
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
	
	public void getAllPeers(bool consoleMessage = true)
	{
		if (!isNatAllow)
		{
			writeln("Self's NAT type not support.");
			return;
		}
		
		ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, this.peerId, string.init);
		socket.sendTo(buffer, new InternetAddress(trackerHost, trackerPort));
		if (consoleMessage) writeln("Request all peers from server.");
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