module app;

import std.stdio;
import std.json;
import std.file;
import std.conv;

import ice;

StunServer[] stunServerList;
string trackerHost;
ushort trackerPort;

void main()
{
	writeln("client.");
	loadConfig();
	
	Peer self = new Peer();
	self.getNatInfo(stunServerList);
	
	writeln("peer id: ", self.peerId);
	writeln(self.natInfo);
	
	string a = self.serialize();
	writeln(a);
	
	Peer p2 = new Peer("test_id", a);
	writeln(p2.natInfo);
}

private void loadConfig()
{
	JSONValue j = parseJSON(std.file.readText("./ice_client.conf"));

	foreach(element; j["stun_servers_list"].array)
	{
		stunServerList ~= StunServer(element["host"].str, element["port"].str.to!ushort);
	}

	JSONValue jt = j["tracker"];
	trackerHost = jt["host"].str;
	trackerPort = jt["port"].str.to!ushort;
}