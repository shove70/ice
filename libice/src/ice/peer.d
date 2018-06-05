module ice.peer;

import std.conv;
import std.bitmanip;

import crypto.base58;

import ice.utils, ice.natinfo;

abstract class Peer
{
    public string peerId;
    public NATInfo natInfo;

    public ubyte[] serialize()
    {
        int offset = 0;
        ubyte[] buffer = new ubyte[int.sizeof + long.sizeof + ushort.sizeof];
        int type = natInfo.natType;
        buffer.write!int(type, offset);
        offset += int.sizeof;
        buffer.write!long(ipToLong(natInfo.externalIp), offset);
        offset += long.sizeof;
        buffer.write!ushort(natInfo.externalPort, offset);
        buffer ~= cast(ubyte[])peerId;

        return buffer;
    }

    void deserialize(ubyte[] buffer)
    {
        natInfo.reset();
        int offset = 0;

        natInfo.natType = cast(NATType)(buffer.peek!int(offset));
        offset += int.sizeof;
        natInfo.externalIp = ipFromLong(buffer.peek!long(offset));
        offset += long.sizeof;
        natInfo.externalPort = buffer.peek!ushort(offset);
        offset += ushort.sizeof;
        peerId = cast(string)buffer[offset..$];
    }

    protected bool verifyPeerId(string input)
    {
        try
        {
            byte[] buffer = Base58.decode(input);
            input = byteToStr_hex(buffer);
        }
        catch (Exception e)
        {
            return false;
        }

        if (input.length != 40)
        {
            return false;
        }

        return (MD5(input[0 .. 32])[0 .. 8] == input[32 .. 40]);
    }
}