module ice.natinfo;

enum NATType
{
    Uninit  = -4,                    // not stuntest.
    Blocked = -3,
    SymmetricUDPFirewall = -2,
    ChangedAddressError  = -1,       // error at stuntest on Changed IP and Port;
    OpenInternet    = 0,
    FullCone        = 1,
    RestrictNAT     = 2,
    RestrictPortNAT = 3,
    SymmetricNAT    = 4,
    UnknownNAT      = 5
}

struct NATInfo
{
    NATType natType = NATType.Uninit;

    string externalIp;
    ushort externalPort = 0;
    string sourceIp;
    ushort sourcePort   = 0;
    string changedIp;
    ushort changedPort  = 0;
    string localIp;
    ushort localPort    = 0;

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

    @property bool natUsable()
    {
        int type = natType;
        return ((type >= 0) && (type <= 4));
    }

    bool canMakeHole(NATInfo poInfo)
    {
        if (!natUsable || !poInfo.natUsable)
            return false;

        if (natType == NATType.RestrictPortNAT)
        {
            if (poInfo.natType == NATType.SymmetricNAT)
                return false;
        }

        if (natType == NATType.SymmetricNAT)
        {
            if ((poInfo.natType == NATType.RestrictPortNAT) || (poInfo.natType == NATType.SymmetricNAT))
                return false;
        }

        return true;
    }

//    string toString()
//    {
//        import std.conv;
//        return "{'ExternalIP': '" ~ externalIp ~ "', 'ExternalPort': " ~ externalPort.to!string ~ ", 'ChangedPort': " ~ changedPort.to!string ~ ", 'SourcePort': " ~ sourcePort.to!string ~ ", 'SourceIP': '" ~ sourceIp ~ "', 'ChangedIP': '" ~ changedIp ~ "'}";
//    }
}