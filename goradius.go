package goradius

import (
	"crypto/md5"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	headerEnd           = 20
	authenticatorLength = 16
)

var (
	VSAs        map[string]VendorSpecificAttribute
	Vendors     map[string]uint32
	VSAsLock    *sync.RWMutex
	VendorsLock *sync.RWMutex
)

type RADIUSMiddleware func(*RadiusServer, *RadiusPacket, *RadiusPacket) (bool, bool)

type RadiusServer struct {
	Secret     string
	handler    func(*RadiusPacket, *RadiusPacket) (bool, bool)   // option 1
	middleware []func(*RadiusPacket, *RadiusPacket) (bool, bool) // option 2
	conn       *net.UDPConn
	Sessions   map[string]bool
	Routes     map[uint8][]RADIUSMiddleware // option 3
	OnDrop     func(*RadiusServer, *RadiusPacket, *RadiusPacket)
	OnReply    func(*RadiusServer, *RadiusPacket, *RadiusPacket)
	Mode       rune
}

// func(req, res) (next, drop)

func (r *RadiusServer) Use(f func(*RadiusPacket, *RadiusPacket) (next, drop bool)) {

	r.middleware = append(r.middleware, f)

}

func NewRadiusServer(mode rune) *RadiusServer {

	r := RadiusServer{}
	r.Mode = mode
	r.Sessions = make(map[string]bool)
	r.Routes = make(map[uint8][]RADIUSMiddleware)

	if VSAs == nil {
		VSAs = make(map[string]VendorSpecificAttribute)
	}

	if Vendors == nil {
		Vendors = make(map[string]uint32)
	}

	if VSAsLock == nil {
		VSAsLock = new(sync.RWMutex)
	}

	if VendorsLock == nil {
		VendorsLock = new(sync.RWMutex)
	}

	return &r
}

func (r *RadiusServer) ListenAndServe(addr_str, secret string) error {

	r.Secret = secret

	addr, err := net.ResolveUDPAddr("udp", addr_str)
	if err != nil {
		log.Fatalln(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	conn.SetReadBuffer(1048576)
	if err != nil {
		log.Fatalln(err)
	}
	r.conn = conn

	for {

		bufr := make([]byte, 4096)
		rawMsgSize, addr, err := conn.ReadFromUDP(bufr)
		if err != nil {
			panic(err)
		}

		go r.handleConn(rawMsgSize, addr, bufr)

	}

}

func (r *RadiusServer) Handler(f func(*RadiusPacket, *RadiusPacket) (bool, bool)) {

	r.handler = f

}

func (r *RadiusServer) handleMiddleware(mid []RADIUSMiddleware, req, res *RadiusPacket) bool {

	for _, m := range mid {

		next, drop := m(r, req, res)

		if drop {
			return true
		}

		if next {
			continue
		}

		if next == false && drop == false {
			break
		}

	}

	return false
}

func (r *RadiusServer) handleConn(rawMsgSize int, addr *net.UDPAddr, data []byte) {

	if rawMsgSize < 20 {
		return // errors.New("Message to short.")
	}

	rawMsg := data[0:rawMsgSize]

	requestPacket, err := ParseRADIUSPacket(rawMsg, r.Secret)
	requestPacket.Addr = addr

	responsePacket := NewRadiusPacket()
	responsePacket.RadiusHeader = requestPacket.RadiusHeader

	drop := true
	routeMatched := false

	var policyFlow []RADIUSMiddleware
	ok := false

	if requestPacket.Code == StatusServer {
		if policyFlow, ok = r.Routes[StatusServer]; ok {
			routeMatched = true
		}
	}

	if requestPacket.Code == AccessRequest {
		if policyFlow, ok = r.Routes[AccessRequest]; ok {
			routeMatched = true
		}
	}

	if requestPacket.Code == AccountingRequest {
		if policyFlow, ok = r.Routes[AccountingRequest]; ok {
			routeMatched = true
		}
	}

	if routeMatched {
		drop = r.handleMiddleware(policyFlow, requestPacket, responsePacket)
	} else {
		log.Printf("routeMatched %v. Did not find route for packet\n%+v", routeMatched, requestPacket)
		log.Printf("Dropping packet. Server mode: %v", r.Mode)
		return
	}

	if drop {
		if r.OnDrop != nil {
			r.OnDrop(r, requestPacket, nil)
		}
		return
	}

	// sometimes we want to silently drop packets
	// so this should be moved out of here.
	err = SendPacket(r.conn, addr, responsePacket, r.Secret)
	if err != nil {
		log.Fatal(err)
	}

	if r.OnReply != nil {
		r.OnReply(r, requestPacket, responsePacket)
	}

	return
}

func CalculateResponseAuthenticator(output []byte, secret string) {

	md5c := md5.New()
	md5c.Write(output)
	md5c.Write([]byte(secret))
	sum := md5c.Sum(nil)

	// Add the new authenticator data
	offset := 4
	for _, bval := range sum {
		output[offset] = bval
		offset += 1
	}
}

func CalculateAuthenticator(output []byte, secret string) {

	md5c := md5.New()
	md5c.Write(output)
	md5c.Write([]byte(secret))
	sum := md5c.Sum(nil)

	// Add the new authenticator data
	offset := 4
	for _, bval := range sum {
		output[offset] = bval
		offset += 1
	}
}

func SendPacket(conn *net.UDPConn, addr *net.UDPAddr, packet *RadiusPacket, secret string) error {

	output, err := packet.EncodePacket(secret)
	if err != nil {
		return err
	}

	if packet.Code == 2 || packet.Code == 5 {
		CalculateResponseAuthenticator(output, secret)
	}

	if packet.Code == 4 {
		CalculateAuthenticator(output, secret)
	}

	bytesWritten, err := conn.WriteToUDP(output, addr)
	if bytesWritten != int(packet.Length) {
		log.Printf("WARNING: Written bytes in UDP socket did not match packet size. Packet: %v Written: %v",
			packet.Length, bytesWritten)
	}

	return err
}

func FindVSA(attr_name string) (VendorSpecificAttribute, error) {

	VSAsLock.RLock()
	vsa, ok := VSAs[attr_name]
	VSAsLock.RUnlock()

	if ok {
		return vsa, nil
	} else {
		return VendorSpecificAttribute{}, errors.New("VSA not found.")
	}
}

func LoadVSAFile(path string) {

	if VSAs == nil {
		VSAs = make(map[string]VendorSpecificAttribute)
	}

	if Vendors == nil {
		Vendors = make(map[string]uint32)
	}

	if VSAsLock == nil {
		VSAsLock = new(sync.RWMutex)
	}

	if VendorsLock == nil {
		VendorsLock = new(sync.RWMutex)
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	data_str := string(data)
	lines := strings.Split(data_str, "\n")

	// Extract all vendors
	expr := `^VENDOR\t(?P<vendor_name>\w+)\t(?P<vendor_id>\d+)$`
	exp, err := regexp.Compile(expr)

	ctr := 0

	VendorsLock.Lock()
	for _, line := range lines {

		if len(line) == 0 {
			continue
		}

		matches := exp.FindStringSubmatch(line)
		if len(matches) > 0 {
			vendor_name := strings.Trim(matches[1], " \t")
			vendor_id_int, _ := strconv.Atoi(matches[2])
			vendor_id := uint32(vendor_id_int)
			Vendors[vendor_name] = vendor_id
			ctr += 1
		}

	}
	VendorsLock.Unlock()

	log.Printf("Vendors loaded: %v", ctr)

	// should match this:
	// s := `ATTRIBUTE	BW-Venue-Id		7	string	Boingo`
	attr_expr := `^ATTRIBUTE\s(?P<attribute>.+)\s(?P<code>\d+)\s(?P<content_type>\w+)\s(?P<vendor_name>\w+)$`
	attr_exp, err := regexp.Compile(attr_expr)
	if err != nil {
		panic(err)
	}

	VendorsLock.RLock()
	VSAsLock.Lock()

	ctr = 0
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		matches := attr_exp.FindStringSubmatch(line)
		if len(matches) == 5 {

			attr_name := strings.Trim(matches[1], " \t")
			attr_code_str := strings.Trim(matches[2], " \t")
			// attr_content_type := strings.Trim(matches[3], " \t")
			attr_vendor := strings.Trim(matches[4], " \t")
			attr_code, _ := strconv.Atoi(attr_code_str)

			// current := fmt.Sprintf("%v %v %v %v", attr_name, attr_code_str, attr_content_type, attr_vendor)

			if _, exists := VSAs[attr_name]; exists {
				log.Printf("[WARNING] Duplicate VSA not stored: %v", attr_name)
			} else {

				vendor_id := Vendors[attr_vendor]

				vsa := VendorSpecificAttribute{
					VendorId:   vendor_id,
					VendorType: uint8(attr_code),
				}

				VSAs[attr_name] = vsa
				ctr += 1

			}

		}
	}

	VendorsLock.RUnlock()
	VSAsLock.Unlock()

	log.Printf("VSAs loaded: %v", ctr)

}
