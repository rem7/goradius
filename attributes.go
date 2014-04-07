package goradius

var (
	UserName               = 1
	UserPassword           = 2
	CHAPPassword           = 3
	NASIPAddress           = 4
	NASPort                = 5
	ServiceType            = 6
	FramedProtocol         = 7
	FramedIPAddress        = 8
	FramedIPNetmask        = 9
	FramedRouting          = 10
	FilterId               = 11
	FramedMTU              = 12
	FramedCompression      = 13
	LoginIPHost            = 14
	LoginService           = 15
	LoginTCPPort           = 16
	ReplyMessage           = 18
	CallbackNumber         = 19
	CallbackId             = 20
	FramedRoute            = 22
	FramedIPXNetwork       = 23
	State                  = 24
	Class                  = 25
	VendorSpecific         = 26
	SessionTimeout         = 27
	IdleTimeout            = 28
	TerminationAction      = 29
	CalledStationId        = 30
	CallingStationId       = 31
	NASIdentifier          = 32
	ProxyState             = 33
	LoginLATService        = 34
	LoginLATNode           = 35
	LoginLATGroup          = 36
	FramedAppleTalkLink    = 37
	FramedAppleTalkNetwork = 38
	FramedAppleTalkZone    = 39
	CHAPChallenge          = 60
	NASPortType            = 61
	PortLimit              = 62
	LoginLATPort           = 63

	code_to_attributes = map[uint8]string{
		1:  "User-Name",
		2:  "User-Password",
		3:  "CHAP-Password",
		4:  "NAS-IP-Address",
		5:  "NAS-Port",
		6:  "Service-Type",
		7:  "Framed-Protocol",
		8:  "Framed-IP-Address",
		9:  "Framed-IP-Netmask",
		10: "Framed-Routing",
		11: "Filter-Id",
		12: "Framed-MTU",
		13: "Framed-Compression",
		14: "Login-IP-Host",
		15: "Login-Service",
		16: "Login-TCP-Port",
		18: "Reply-Message",
		19: "Callback-Number",
		20: "Callback-Id",
		22: "Framed-Route",
		23: "Framed-IPX-Network",
		24: "State",
		25: "Class",
		26: "Vendor-Specific",
		27: "Session-Timeout",
		28: "Idle-Timeout",
		29: "Termination-Action",
		30: "Called-Station-Id",
		31: "Calling-Station-Id",
		32: "NAS-Identifier",
		33: "Proxy-State",
		34: "Login-LAT-Service",
		35: "Login-LAT-Node",
		36: "Login-LAT-Group",
		37: "Framed-AppleTalk-Link",
		38: "Framed-AppleTalk-Network",
		39: "Framed-AppleTalk-Zone",
		60: "CHAP-Challenge",
		61: "NAS-Port-Type",
		62: "Port-Limit",
		63: "Login-LAT-Port",
	}

	attributes_to_code = map[string]uint8{
		"User-Name":                1,
		"User-Password":            2,
		"CHAP-Password":            3,
		"NAS-IP-Address":           4,
		"NAS-Port":                 5,
		"Service-Type":             6,
		"Framed-Protocol":          7,
		"Framed-IP-Address":        8,
		"Framed-IP-Netmask":        9,
		"Framed-Routing":           10,
		"Filter-Id":                11,
		"Framed-MTU":               12,
		"Framed-Compression":       13,
		"Login-IP-Host":            14,
		"Login-Service":            15,
		"Login-TCP-Port":           16,
		"Reply-Message":            18,
		"Callback-Number":          19,
		"Callback-Id":              20,
		"Framed-Route":             22,
		"Framed-IPX-Network":       23,
		"State":                    24,
		"Class":                    25,
		"Vendor-Specific":          26,
		"Session-Timeout":          27,
		"Idle-Timeout":             28,
		"Termination-Action":       29,
		"Called-Station-Id":        30,
		"Calling-Station-Id":       31,
		"NAS-Identifier":           32,
		"Proxy-State":              33,
		"Login-LAT-Service":        34,
		"Login-LAT-Node":           35,
		"Login-LAT-Group":          36,
		"Framed-AppleTalk-Link":    37,
		"Framed-AppleTalk-Network": 38,
		"Framed-AppleTalk-Zone":    39,
		"CHAP-Challenge":           60,
		"NAS-Port-Type":            61,
		"Port-Limit":               62,
		"Login-LAT-Port":           63,
	}
)
