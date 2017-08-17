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

public T[] strToByte_hex(T = byte)(string input)
{
	Appender!(T[]) app;
	for (int i; i < input.length; i += 2)
	{
		app ~= input[i .. i + 2].to!T(16);
	}
	return app.data;
}

public string byteToStr_hex(T = byte)(T[] buffer)
{
	Appender!string app;
	foreach (b; buffer)
	{
		app ~= rightJustify(b.to!string(16).toUpper(), 2, '0');
	}
	return app.data;
}