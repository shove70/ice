module ice.packet;

import std.stdio;
import std.bitmanip;
import std.array;
import std.string;
import std.conv;
import std.typecons;

import ice.utils, ice.natinfo, ice.peerother;

enum Cmd
{
    ReportPeerInfo           = 1,
    RequestAllPeers          = 2,    
    PostMessageDirect        = 3,
    PostMessageForward       = 4,
    RequestMakeHoleDirect    = 5,
    RequestMakeHoleForward   = 6,
    ResponseMakeHole         = 7,
    Heartbeat                = 8
}

/**
protocol rule (TLV):

magic_number(ushort) ~ total_len(ushort) ~ cmd(byte) ~ sender_nattype(byte) ~ len(byte)+senderId(string) ~ len(byte)+po_serialize(ubyte[]) ~ len(ushort)+data(string) ~ ushort(hash(all)[0..4])

cmd:

1: report a peer info (for client self): 1,nat,id,"",""        -> server reply:    1,"","","",""
2: request all peers from server.      : 2,nat,id,"",""     -> server reply:    2,"","","",len~serialize...
3: postmessage(direct send)            : 3,nat,id,"",data    -> none
4: postmessage(forward)                : 4,nat,id,po,data    -> server forward:    4,"","",po,data [exchange po]
5: request make hole(direct)           : 5,nat,id,"",""        -> po reply peer:    7,nat,id,"",""
6: request make hole(forward)          : 6,nat,id,po,""        -> server forward:    6,"","",po,""    [exchange po] -> po reply: -> peer: 7,nat,id,"",""
8: heartbeat(two)                      : 8,nat,id,"",""        -> none
                                       : magic_number
*/

struct Packet
{
    Cmd            cmd;
    NATType        senderNatType;
    string         senderPeerId;
    PeerOther      additionalPo;
    ubyte[]        data;

    static ubyte[] build(ushort magicNumber)    // for heartbeat
    {
        ubyte[] buffer = new ubyte[2];
        buffer.write!ushort(magicNumber, 0);

        return buffer;
    }

    static ubyte[] build(ushort magicNumber, Cmd cmd, NATType senderNatType = NATType.Uninit, string senderPeerId = string.init, PeerOther additionalPo = null, ubyte[] data = null)
    {
        ubyte[] sender_buf = cast(ubyte[])senderPeerId;
        ubyte[] additional_buf = (additionalPo is null) ? new ubyte[0] : additionalPo.serialize;
        ubyte[] data_buf = cast(ubyte[])data;
        ulong total_len = sender_buf.length + additional_buf.length + data_buf.length + 7;

        assert(total_len <= 65503);

        ubyte[] buffer = new ubyte[4];
        buffer.write!ushort(magicNumber, 0);
        buffer.write!ushort(cast(ushort)total_len, 2);

        int icmd = cmd;
        buffer ~= cast(ubyte)icmd;
        int itype = senderNatType;
        buffer ~= cast(ubyte)itype;

        buffer ~= cast(ubyte)(sender_buf.length);
        buffer ~= sender_buf;
        buffer ~= cast(ubyte)(additional_buf.length);
        buffer ~= additional_buf;
        buffer ~= cast(ubyte)(data_buf.length);
        buffer ~= data_buf;
        buffer ~= strToByte_hex(MD5(buffer)[0..4]);

        return buffer;
    }

    static Nullable!Packet parse(ushort magicNumber, ubyte[] buffer)
    {
        ushort t_magic, t_len, t_crc;
        Packet packet;

        if (buffer.length == 2)    // for heartbeat
        {
            t_magic = buffer.peek!ushort(0);

            if (t_magic != magicNumber)
            {
                return Nullable!Packet();
            }

            packet.cmd = Cmd.Heartbeat;

            return Nullable!Packet(packet);
        }

        if (buffer.length < 11)
        {
            return Nullable!Packet();
        }

        t_magic = buffer.peek!ushort(0);
        t_len = buffer.peek!ushort(2);

        if ((t_magic != magicNumber) || (t_len > buffer.length - 4))
        {
            return Nullable!Packet();
        }

        buffer = buffer[0..t_len + 4];
        t_crc = buffer.peek!ushort(buffer.length - 2);

        if (strToByte_hex(MD5(buffer[0..$ - 2])[0..4]) != buffer[$ - 2..$])
        {
            return Nullable!Packet();
        }

        buffer = buffer[4..$ - 2];

        packet.cmd = cast(Cmd)(buffer[0]);
        packet.senderNatType = cast(NATType)(buffer[1]);
        buffer = buffer[2..$];

        t_len = buffer[0];
        packet.senderPeerId = cast(string)buffer[1..t_len + 1];
        buffer = buffer[1 + t_len..$];

        t_len = buffer[0];
        if (t_len > 0)
        {
            packet.additionalPo = new PeerOther(buffer[1..t_len + 1]);
        }
        buffer = buffer[1 + t_len..$];

        t_len = buffer[0];
        packet.data = buffer[1..$];

        return Nullable!Packet(packet);
    }
}