package goradius

import (
	"log"
	"net"
)

const (
	headerEnd           = 20
	authenticatorLength = 16
)

type RADIUSMiddleware func(*RadiusServer, *RadiusPacket, *RadiusPacket) (bool, bool)

type RadiusServer struct {
	Secret string
	// still debating  how we want to handle the policy flow...
	// do we have one handler and let the programmer deal with
	// the flow, or
	// do we do it middleware style were we jump from one
	// function to the next...
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

	// _, drop := r.handler(requestPacket, responsePacket)
	// if drop {
	// 	return
	// }

	if drop {
		if r.OnDrop != nil {
			r.OnDrop(r, requestPacket, nil)
		}
		return
	}

	// sometimes we want to silently drop packets
	// so this should be moved out of here.
	err = SendRADIUSPacket(r.conn, addr, responsePacket, r.Secret, true)
	if err != nil {
		log.Fatal(err)
	}

	if r.OnReply != nil {
		r.OnReply(r, requestPacket, responsePacket)
	}

	return
}

func SendRADIUSPacket(conn *net.UDPConn, addr *net.UDPAddr, responsePacket *RadiusPacket, secret string, recalculateAuthenticator bool) error {

	output, err := EncodeRADIUSPacket(responsePacket, secret, recalculateAuthenticator)
	if err != nil {
		return err
	}

	bytesWritten, err := conn.WriteToUDP(output, addr)
	if bytesWritten != int(responsePacket.Length) {
		log.Printf("WARNING: Written bytes in UDP socket did not match packet size. Packet: %v Written: %v",
			responsePacket.Length, bytesWritten)
	}

	return err
}

func checkErr(msg string, err error) {
	if err != nil {
		log.Printf("%v %v", msg, err.Error())
	}
}
