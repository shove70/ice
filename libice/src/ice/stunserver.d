module ice.stunserver;

 struct StunServer
{
    string host;
    ushort port;

    this(string host, ushort port)
    {
        this.host = host;
        this.port = port;
    }
}