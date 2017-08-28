module ice.peerother;

import std.socket;
import std.conv;

import ice.peer, ice.natinfo;

final class PeerOther : Peer
{
	public bool hasHole = false;
	public bool consulting = false;
	
	this(string peerId, ubyte[] serializedBuffer)
	{
		this.peerId = peerId;
		deserialize(serializedBuffer);
	}
	
	this(string peerId, string serializedString)
	{
		this.peerId = peerId;
		deserialize(serializedString);
	}
	
	this(string peerId, NATType natType, Address address)
	{
		this.peerId = peerId;
		this.natInfo.natType = natType;
		this.natInfo.externalIp = address.toAddrString();
		this.natInfo.externalPort = address.toPortString().to!ushort;
	}
}