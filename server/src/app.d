module app;

import std.stdio;
import std.conv;
import std.json;
import std.file;
import core.thread;
import std.concurrency;
import std.socket;
import std.bitmanip;
import std.typecons;
import std.datetime;

import ice;

string host;
ushort port;
__gshared ushort magicNumber;

__gshared PeerOther[string] peers;
__gshared UdpSocket socket;

void main()
{
    writeln("ice server.");
    loadConfig();
    loadPeers();

    startListen();
}

void startListen()
{
    socket = new UdpSocket();
    socket.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, true);
    socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, dur!"seconds"(5));
    socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, dur!"seconds"(5));
    socket.bind(new InternetAddress(host, port));

    writefln("Listening on port %d.", port);
    spawn!()(&listener);
    spawn!()(&savePeers);
}

void listener()
{
    while (true)
    {
        Address address = new InternetAddress(InternetAddress.ADDR_ANY, InternetAddress.PORT_ANY);

        ubyte[] buffer = new ubyte[65507];
        socket.receiveFrom(buffer, address);
        spawn!()(&handler, cast(shared ubyte[])buffer, cast(shared Address)address);
    }
}

private void handler(shared ubyte[] _receiveData, shared Address _address)
{
    ubyte[] receiveData = cast(ubyte[])_receiveData;
    Address address        = cast(Address)_address;
    Nullable!Packet packet = Packet.parse(magicNumber, receiveData);

    if (packet.isNull)
    {
        return;
    }

    PeerOther parseSender()
    {
        if (packet.senderPeerId == string.init)
        {
            return null;
        }

        PeerOther po;

        if (packet.senderPeerId !in peers)
        {
            peers[packet.senderPeerId] = new PeerOther(packet.senderPeerId, packet.senderNatType, address);
            po = peers[packet.senderPeerId];
        }
        else
        {
            po = peers[packet.senderPeerId];
            po.natInfo.natType = packet.senderNatType;
            po.natInfo.externalIp = address.toAddrString();
            po.natInfo.externalPort = address.toPortString().to!ushort;
        }

        po.lastHeartbeat = currTimeTick;

        return po;
    }

    PeerOther parseAdditionalPo()
    {
        if (packet.additionalPo is null)
        {
            return null;
        }

        PeerOther po;

        if (packet.additionalPo.peerId !in peers)
        {
            peers[packet.additionalPo.peerId] = packet.additionalPo;
            po = peers[packet.additionalPo.peerId];
        }
        else
        {
            po = peers[packet.additionalPo.peerId];
            //po.natInfo.natType = packet.senderNatType;        // The sender cannot be trusted with the latest results
            //po.natInfo.externalIp = address.toAddrString();
            //po.natInfo.externalPort = address.toPortString().to!ushort;        
        }

        return po;
    }

    final switch (packet.cmd)
    {
        case Cmd.ReportPeerInfo:
            PeerOther po = parseSender();
            if (po is null) break;
            ubyte[] buffer = Packet.build(magicNumber, Cmd.ReportPeerInfo);
            socket.sendTo(buffer, address);
            break;
        case Cmd.RequestAllPeers:
            if (parseSender() is null) break;

            void sendResult(ubyte[] response)
            {
                if (response.length == 0) return;
                ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestAllPeers, NATType.Uninit, string.init, null, response);
                socket.sendTo(buffer, address);
            }

            ubyte[] response = new ubyte[0];
            foreach(v; peers)
            {
                ubyte[] serialized = v.serialize;
                response ~= cast(ubyte)serialized.length;
                response ~= serialized;
                if (response.length > 65000)
                {
                    sendResult(response);
                    response = new ubyte[0];
                }
            }
            sendResult(response);
            break;
        case Cmd.PostMessageDirect:
            parseSender();
            break;
        case Cmd.PostMessageForward:
            PeerOther po = parseSender();
            if (po is null)                        break;
            PeerOther additionalPo = parseAdditionalPo();
            if (additionalPo is null)            break;
            ubyte[] buffer = Packet.build(magicNumber, Cmd.PostMessageForward, NATType.Uninit, string.init, po, packet.data);
            socket.sendTo(buffer, new InternetAddress(additionalPo.natInfo.externalIp, additionalPo.natInfo.externalPort));
            break;
        case Cmd.RequestMakeHoleDirect:
            parseSender();
            break;
        case Cmd.RequestMakeHoleForward:
            PeerOther po = parseSender();
            if (po is null)                        break;
            PeerOther additionalPo = parseAdditionalPo();
            if (additionalPo is null)            break;
            ubyte[] buffer = Packet.build(magicNumber, Cmd.RequestMakeHoleForward, NATType.Uninit, string.init, po);
            socket.sendTo(buffer, new InternetAddress(additionalPo.natInfo.externalIp, additionalPo.natInfo.externalPort));
            break;
        case Cmd.ResponseMakeHole:
            parseSender();
            break;
        case Cmd.Heartbeat:
            if (packet.senderPeerId != string.init)
            {
                parseSender();
            }
            ubyte[] buffer = Packet.build(magicNumber);    // minimize it.
            socket.sendTo(buffer, address);
            break;
    }
}

private void loadPeers()
{
    string path = "./.caches";
    string fileName = "./.caches/.peers";

    if (!std.file.exists(path))
    {
        try
        {
            std.file.mkdirRecurse(path);
        }
        catch (Exception e) { }
    }

    if (!std.file.exists(fileName))
    {
        return;
    }

    peers.clear;
    JSONValue json = parseJSON(cast(string)std.file.readText(fileName));

    foreach(JSONValue j; json.array)
    {
        PeerOther po            = new PeerOther(j["id"].str);
        po.natInfo.natType        = cast(NATType)(cast(int)(j["t"].integer));
        po.natInfo.externalIp    = j["ei"].str;
        po.natInfo.externalPort    = cast(ushort)(j["ep"].integer);
        //po.natInfo.localIp        = j["li"].str;
        //po.natInfo.localPort    = cast(ushort)(j["lp"].integer);
        po.discoveryTime        = j["dt"].integer;
        po.lastHeartbeat        = j["ht"].integer;

        peers[po.peerId]        = po;
    }
}

private void savePeers()
{
    void save()
    {
        string path = "./.caches";
        string fileName = "./.caches/.peers";

        if (!std.file.exists(path))
        {
            try
            {
                std.file.mkdirRecurse(path);
            }
            catch (Exception e) { }
        }

        JSONValue json = [null];
        json.array.length = 0;

        foreach(PeerOther po; peers)
        {
            JSONValue j = ["id": "", "t": "0", "ei": "", "ep": "0", /*"li": "", "lp": "0", */"dt": "0", "ht": "0"];
            j["id"].str        = po.peerId;
            int type        = po.natInfo.natType;
            j["t"].integer    = type;
            j["ei"].str        = po.natInfo.externalIp;
            j["ep"].integer    = po.natInfo.externalPort;
            //j["li"].str        = po.natInfo.localIp;
            //j["lp"].integer    = po.natInfo.localPort;
            j["dt"].integer    = po.discoveryTime;
            j["ht"].integer    = po.lastHeartbeat;
            json.array ~= j;
        }

        std.file.write(fileName, cast(byte[])json.toString());
    }

    while (true)
    {
        Thread.sleep(1.minutes);

        save();
    }
}

private void loadConfig()
{
    JSONValue j = parseJSON(std.file.readText("./ice_tracker.conf"));

    JSONValue jt = j["tracker"];
    host = jt["host"].str;
    port = jt["port"].str.to!ushort;

    jt = j["protocol"];
    magicNumber = jt["magic number"].str.to!ushort;
}
