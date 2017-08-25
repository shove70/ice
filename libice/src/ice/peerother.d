module ice.peerother;

import ice.peer;

final class PeerOther : Peer
{
	public bool hasHole = false;
	public bool consulting = false;
	
	this(string peerId, string serializedString)
	{
		this.peerId = peerId;
		deserialize(serializedString);
	}
}