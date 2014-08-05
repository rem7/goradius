package goradius

const (
	AUTH = iota
	ACCT
)

const (
	AcctStart     = 1
	AcctStop      = 2
	InterimUpdate = 3
	AccountingOn  = 7
	AccountingOff = 8
)

var (
	AccessRequest      = uint8(1)
	AccessAccept       = uint8(2)
	AccessReject       = uint8(3)
	AccountingRequest  = uint8(4)
	AccountingResponse = uint8(5)
	AccessChallenge    = uint8(11)
	StatusServer       = uint8(12)
	StatusClient       = uint8(13)

	UserName               = uint8(1)
	UserPassword           = uint8(2)
	CHAPPassword           = uint8(3)
	NASIPAddress           = uint8(4)
	NASPort                = uint8(5)
	ServiceType            = uint8(6)
	FramedProtocol         = uint8(7)
	FramedIPAddress        = uint8(8)
	FramedIPNetmask        = uint8(9)
	FramedRouting          = uint8(10)
	FilterId               = uint8(11)
	FramedMTU              = uint8(12)
	FramedCompression      = uint8(13)
	LoginIPHost            = uint8(14)
	LoginService           = uint8(15)
	LoginTCPPort           = uint8(16)
	ReplyMessage           = uint8(18)
	CallbackNumber         = uint8(19)
	CallbackId             = uint8(20)
	FramedRoute            = uint8(22)
	FramedIPXNetwork       = uint8(23)
	State                  = uint8(24)
	Class                  = uint8(25)
	VendorSpecific         = uint8(26)
	SessionTimeout         = uint8(27)
	IdleTimeout            = uint8(28)
	TerminationAction      = uint8(29)
	CalledStationId        = uint8(30)
	CallingStationId       = uint8(31)
	NASIdentifier          = uint8(32)
	ProxyState             = uint8(33)
	LoginLATService        = uint8(34)
	LoginLATNode           = uint8(35)
	LoginLATGroup          = uint8(36)
	FramedAppleTalkLink    = uint8(37)
	FramedAppleTalkNetwork = uint8(38)
	FramedAppleTalkZone    = uint8(39)
	AcctStatusType         = uint8(40)
	AcctDelayTime          = uint8(41)
	AcctInputOctets        = uint8(42)
	AcctOutputOctets       = uint8(43)
	AcctSessionId          = uint8(44)
	AcctAuthentic          = uint8(45)
	AcctSessionTime        = uint8(46)
	AcctInputPackets       = uint8(47)
	AcctOutputPackets      = uint8(48)
	AcctTerminateCause     = uint8(49)
	AcctMultiSessionId     = uint8(50)
	AcctLinkCount          = uint8(51)
	CHAPChallenge          = uint8(60)
	NASPortType            = uint8(61)
	PortLimit              = uint8(62)
	LoginLATPort           = uint8(63)

	request_type_to_string = map[uint8]string{
		1:  "AccessRequest",
		2:  "AccessAccept",
		3:  "AccessReject",
		4:  "AccountingRequest",
		5:  "AccountingResponse",
		11: "AccessChallenge",
		12: "StatusServer",
		13: "StatusClient",
	}

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
		40: "Acct-Status-Type",
		41: "Acct-Delay-Time",
		42: "Acct-Input-Octets",
		43: "Acct-Output-Octets",
		44: "Acct-Session-Id",
		45: "Acct-Authentic",
		46: "Acct-Session-Time",
		47: "Acct-Input-Packets",
		48: "Acct-Output-Packets",
		49: "Acct-Terminate-Cause",
		50: "Acct-Multi-Session-Id",
		51: "Acct-Link-Count",
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
		"Acct-Status-Type":         40,
		"Acct-Delay-Time":          41,
		"Acct-Input-Octets":        42,
		"Acct-Output-Octets":       43,
		"Acct-Session-Id":          44,
		"Acct-Authentic":           45,
		"Acct-Session-Time":        46,
		"Acct-Input-Packets":       47,
		"Acct-Output-Packets":      48,
		"Acct-Terminate-Cause":     49,
		"Acct-Multi-Session-Id":    50,
		"Acct-Link-Count":          51,
		"CHAP-Challenge":           60,
		"NAS-Port-Type":            61,
		"Port-Limit":               62,
		"Login-LAT-Port":           63,
	}
)
