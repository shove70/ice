module ice.peerother;

import std.socket;
import std.conv;
import std.datetime;

import ice.peer, ice.natinfo;

final class PeerOther : Peer
{
	public bool hasHole = false;
	public bool consulting = false;
	public DateTime discoveryTime;
	public int tryConnectTimes = 0;
	public DateTime lastHeartbeat;
	
	this(string peerId, ubyte[] serializedBuffer)
	{
		this(peerId, cast(string)serializedBuffer);
	}
	
	this(string peerId, string serializedString)
	{
		this.peerId = peerId;
		discoveryTime = cast(DateTime)Clock.currTime();
		deserialize(serializedString);
	}
	
	this(string peerId, NATType natType, Address address)
	{
		this.peerId = peerId;
		discoveryTime = cast(DateTime)Clock.currTime();
		
		this.natInfo.natType = natType;
		this.natInfo.externalIp = address.toAddrString();
		this.natInfo.externalPort = address.toPortString().to!ushort;
	}
}