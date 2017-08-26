module ice.utils;

import std.uuid;
import std.random;
import std.conv;
import std.string;
import std.digest.md;
import std.file;
import std.array;

import cryption.tea.xtea;

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

public string ipFromLong(long ipInt)
{
	string[4] part;
	
	for (int i = 3; i >= 0; i--)
	{
		part[i] = to!string(ipInt % 256);
		ipInt /= 256;
	}
	
	return join([
		part[0].to!string, ".",
		part[1].to!string, ".",
		part[2].to!string, ".",
		part[3].to!string]
	);
}

public bool isLoopbackIpAddress(string ip) //127.0.0.1 -> 127.255.255.254
{
	long ipLong = ipToLong(ip);
	return ((ipLong >= 2130706433) && (ipLong <= 2147483646));
}

public alias xtea!(Xtea.encrypt) xteaEncrypt;
public alias xtea!(Xtea.decrypt) xteaDecrypt;

public ubyte[] xtea(alias T)(ubyte[] input, string key)
{
	ubyte[] buf = cast(ubyte[])key;
	int[4] bkey = [buf[0], buf[1], buf[2], buf[3]];
	int rounds = 64;
	
	return T(input, bkey, rounds, true);
}