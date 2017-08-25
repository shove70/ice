module ice.natinfo;

import ice.nattype;

struct NATInfo
{
	NATType natType = NATType.Uninit;
	
	string externalIp;
	ushort externalPort = 0;
	string sourceIp;
	ushort sourcePort = 0;
	string changedIp;
	ushort changedPort = 0;
	string localIp;
	ushort localPort = 0;

	void reset()
	{
		natType = NATType.Uninit;
		
		externalIp = string.init;
		externalPort = 0;
		sourceIp = string.init;
		sourcePort = 0;
		changedIp = string.init;
		changedPort = 0;
		localIp = "0.0.0.0";
		localPort = 0;
	}

//	string toString()
//	{
//		import std.conv;
//		return "{'ExternalIP': '" ~ externalIp ~ "', 'ExternalPort': " ~ externalPort.to!string ~ ", 'ChangedPort': " ~ changedPort.to!string ~ ", 'SourcePort': " ~ sourcePort.to!string ~ ", 'SourceIP': '" ~ sourceIp ~ "', 'ChangedIP': '" ~ changedIp ~ "'}";
//	}
}