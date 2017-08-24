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
	self.startListen(
		(string fromPeerId, string toPeerId, ubyte[] data)
		{
			onReceive(fromPeerId, toPeerId, data);
		}
	);
	self.getAllPeers();
	self.connectPeers();
	
	showMenu();
	
	string line;
    while ((line = readln()) !is null)
	{
		line = line[0..$ - 1];		
		if (line == string.init)
			continue;
			
		if (line == "exit")
		{
			import core.stdc.stdlib;
			exit(0);
			return;
		}
				
		if (line == "peers")
		{
			if (!trackerConnected)
			{
				writeln("Not connection to tracker(server).");
			}
			self.getAllPeers();
			self.connectPeers();
			showMenu();
		    continue;
	    }
		
		writefln("Self sent to all: %s", line);
		self.broadcastMessage(cast(ubyte[])line);
	}
}

void showMenu()
{
	writeln();
	writeln("All peers:");
	for(int i; i < peers.keys.length; i++)
	{
		writefln("%d: %s [%s]", i + 1, peers.keys[i], peers[peers.keys[i]].hasHole ? "Connected" : "Not conn");
	}
	writeln("Menu:");
	writeln("1. press the \"peers\" to request all peers from server.");
	writeln("2. press other string will be send to all peers.");
	writeln("3. press \"exit\" to exit the client.");
	write("Please input: ");
}

void onReceive(string fromPeerId, string toPeerId, ubyte[] data)
{
	writefln("%s sent to %s: %s", fromPeerId, toPeerId, cast(string)data);
}
