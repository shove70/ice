module ice.utils;

import std.uuid;
import std.random;
import std.conv;
import std.string;
import std.digest.md;
import std.file;
import std.array;
import std.socket;
import std.datetime;

import crypto.tea.xtea;

public string genUuid()
{
	Xorshift192 gen;
	gen.seed(unpredictableSeed);
	auto uuid = randomUUID(gen);
	return uuid.toString.replace("-", "").toUpper();
}

public string MD5(scope const(void[])[] src...)
{
	auto md5 = new MD5Digest();
	ubyte[] hash = md5.digest(src);
	
    return toHexString(hash).toUpper();
}

public ubyte[] strToByte_hex(string input)
{
	Appender!(ubyte[]) app;
	for (int i; i < input.length; i += 2)
	{
		app.put(input[i .. i + 2].to!ubyte(16));
	}
	
	return app.data;
}

public string byteToStr_hex(T = byte)(T[] buffer)
{
	Appender!string app;
	foreach (b; buffer)
	{
		app.put(rightJustify(b.to!string(16).toUpper(), 2, '0'));
	}
	return app.data;
}

public long ipToLong(string ip)
{
	auto part = split(ip, ".");
	assert(part.length == 4);
	
	long r = to!long(part[3]);
	
	for (int i = 2; i >= 0; i--)
	{
		r += to!long(part[i]) << 8 * (3 - i);
	}
	
	return r;
}

public string ipFromLong(long ipLong)
{
	string[4] part;
	
	for (int i = 3; i >= 0; i--)
	{
		part[i] = to!string(ipLong % 256);
		ipLong /= 256;
	}
	
	return join([
		part[0].to!string, ".",
		part[1].to!string, ".",
		part[2].to!string, ".",
		part[3].to!string]
	);
}

public string getLocalIpAddress()
{
	import core.stdc.stdlib;
	
	int ret;
	
	version(Posix)
	{
		import core.sys.posix.unistd;
		import core.sys.posix.netdb;
	}
	else version(Windows)
	{
		import core.sys.windows.winsock2;
		
		WSADATA wsaData;  
		ret = WSAStartup(MAKEWORD(2, 2), &wsaData);  
		if (ret != 0)  
		{  
			writeln("Error.");
			returnstring.init;  
		}
	}
	
	char* hostname = cast(char*)malloc(1024 + 1);		
	ret = gethostname(hostname, 1024);
	version(Windows) { WSACleanup(); }
	
	if (ret < 0)
	{
		return string.init;
	}
	
	string hostName = cast(string)fromStringz(hostname);
	hostname.destroy();
	
	AddressInfo[] ai = getAddressInfo(hostName);
	foreach(AddressInfo addr; ai)
	{
		if (addr.family == AddressFamily.INET)
		{
			if (isLanIpAddress(addr.address.toAddrString()))
			{
				return addr.address.toAddrString();
			}
		}
	}
	
	return string.init;
}

public bool isLoopbackIpAddress(string ip) //127.0.0.1 -> 127.255.255.254
{
	long ipLong = ipToLong(ip);
	return ((ipLong >= 2130706433) && (ipLong <= 2147483646));
}

public bool isLanIpAddress(string ip)
{
	/*
	A 10.0.0.0		--	10.255.255.255
	B 172.16.0.0	--	172.31.255.255
	C 192.168.0.0	--	192.168.255.255
	*/
	long ipLong = ipToLong(ip);
	return (
		((ipLong >= 167772160)  && (ipLong <= 184549375)) ||
		((ipLong >= 2886729728) && (ipLong <= 2887778303)) ||
		((ipLong >= 3232235520) && (ipLong <= 3232301055))
	);
}

private const long TICK_BASE = 1460004240;

public long currTimeTick()
{
	return Clock.currTime().toUnixTime() - TICK_BASE;
}

public SysTime currTimeFromTick(long tick)
{
	return SysTime.fromUnixTime(tick + TICK_BASE);
}