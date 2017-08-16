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
	
	IceClient client = new IceClient(stunServerList, trackerHost, trackerPort);
	
	writeln(client.NAT_Info());

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