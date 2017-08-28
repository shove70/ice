module app;

import std.stdio;
import std.conv;
import std.string;

import ice.all;

PeerSelf self;

void main()
{
	writeln("ice client.");
	
	self = new PeerSelf();
	self.autoConnectPeerOthers = true;
	self.start(
		(string fromPeerId, string toPeerId, ubyte[] data, bool isForward)
		{
			onReceive(fromPeerId, toPeerId, data, isForward);
		}
	);
	
	showMenu();
	
	string line;
    while ((line = readln()) !is null)
	{
		line = line[0..$ - 1];		
		if (line == string.init)
		{
			write("Please input: ");
			continue;
		}
			
		if (line == "exit")
		{
			writeln("bye.\n");
			import core.stdc.stdlib;
			exit(0);
			return;
		}
				
		if (line == "menu")
		{
			showMenu();
		    continue;
	    }
		
		writeln("Please input: ");
		self.broadcastMessage(cast(ubyte[])line);
	}
}

void showMenu()
{
	writeln();	
	if (!trackerConnected) writeln("Not connection to tracker(server).");

	writeln("All peers:");
	for(int i; i < peers.keys.length; i++)
	{
		PeerOther po = peers[peers.keys[i]];
		writefln("%d: %s: %s:%d [%s]%s", i + 1, peers.keys[i], po.natInfo.externalIp, po.natInfo.externalPort, po.hasHole ? "Connected" : "Not conn", (peers.keys[i] == self.peerId) ? "[self]" : "");
	}
	writeln("Menu:");
	writeln("1. press the \"menu\" to show this menu items.");
	writeln("2. press a string will be send to all peers.");
	writeln("3. press \"exit\" to exit the client.");
	writeln("Please input: ");
}

void onReceive(string fromPeerId, string toPeerId, ubyte[] data, bool isForward)
{
	writefln("%s sent to %s%s: %s", fromPeerId, toPeerId, isForward ? "[Forward]" : "", cast(string)data);
	writeln("Please input: ");
}
