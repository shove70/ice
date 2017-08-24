module ice.peerother;

import ice.peer;

final class PeerOther : Peer
{
	public bool hasHole = false;
	
	this(string peerId, string serializedString)
	{
		this.peerId = peerId;
		deserialize(serializedString);
	}
}