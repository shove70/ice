module utils;

import std.uuid;
import std.random;
import std.conv;
import std.string;
import std.digest.md;
import std.file;
import std.array;

public string genUuid()	// RFC3489 128bits transaction ID
{
	Xorshift192 gen;
	gen.seed(unpredictableSeed);
	auto uuid = randomUUID(gen);
	return uuid.toString.replace("-", "").toUpper();
}

public string MD5(string T = "string")(string src)
{
	assert(T == "string" || T == "file");
	
	auto md5 = new MD5Digest();
	ubyte[] hash = (T == "string") ? md5.digest(src) : md5.digest(std.file.read(src));
	
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
	
	return mergeString(
		part[0].to!string, ".",
		part[1].to!string, ".",
		part[2].to!string, ".",
		part[3].to!string
	);
}

public string mergeString(Params...)(Params params)
{
	Appender!string ret;
	
	foreach(str; params)
	{
		ret.put(str);
	}
	
	return ret.data;
}