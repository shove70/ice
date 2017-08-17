module nattype;

enum NATType
{
	Uninit = -4,					// not stuntest.
	Blocked = -3,
	SymmetricUDPFirewall = -2,
	ChangedAddressError = -1,		// error at stuntest on Changed IP and Port;
	OpenInternet = 0,
	FullCone = 1,
	RestrictNAT = 2,
	RestrictPortNAT = 3,
	SymmetricNAT = 4,
	UnknownNAT = 5
}