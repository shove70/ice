module ice.peerother;

import std.socket;
import std.conv;

import ice.utils, ice.peer, ice.natinfo;

final class PeerOther : Peer
{
	public bool hasHole = false;
	public bool consulting = false;
	public long discoveryTime = 0;
	public int tryConnectTimes = 0;
	public long lastHeartbeat = 0;
	
	this(string peerId)
	{
		this.peerId = peerId;
	}
	
	this(ubyte[] serializedBuffer)
	{
		deserialize(serializedBuffer);
		discoveryTime = currTimeTick;
	}
	
	this(string peerId, NATType natType, Address address)
	{
		this.peerId = peerId;
		discoveryTime = currTimeTick;
		
		this.natInfo.natType = natType;
		this.natInfo.externalIp = address.toAddrString();
		this.natInfo.externalPort = address.toPortString().to!ushort;
	}
}