package goradius

import (
	"log"
	"net"
)

const (
	headerEnd           = 20
	authenticatorLength = 16
)

type RadiusServer struct {
	Secret string
	// still debating  how we want to handle the policy flow...
	// do we have one handler and let the programmer deal with
	// the flow, or
	// do we do it middleware style were we jump from one
	// function to the next...
	handler    func(req *RadiusPacket, res *RadiusPacket) error // option 1
	middleware []func(*RadiusPacket, *RadiusPacket) error       // option 2
	conn       *net.UDPConn
}

func (r *RadiusServer) Use(f func(*RadiusPacket, *RadiusPacket) error) {

	r.middleware = append(r.middleware, f)

}

func (r *RadiusServer) ListenAndServe(addr_str, secret string) error {

	r.Secret = secret

	addr, err := net.ResolveUDPAddr("udp", addr_str)
	if err != nil {
		log.Fatalln(err)
	}

	conn, err := net.ListenUDP("udp", addr)
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

		r.handleConn(rawMsgSize, addr, bufr)

	}

}

func (r *RadiusServer) Handler(f func(*RadiusPacket, *RadiusPacket) error) {

	r.handler = f

}

func (r *RadiusServer) handleConn(rawMsgSize int, addr *net.UDPAddr, data []byte) {

	if rawMsgSize < 20 {
		return // errors.New("Message to short.")
	}

	rawMsg := data[0:rawMsgSize]

	requestPacket, err := ParseRADIUSPacket(rawMsg, r.Secret)

	responsePacket := NewRadiusPacket()
	responsePacket.RadiusHeader = requestPacket.RadiusHeader

	for _, m := range r.middleware {
		e := m(requestPacket, responsePacket)

		// silently drop package if we get an error.
		if e != nil {
			return
		}
	}

	// err = r.handler(requestPacket, responsePacket)
	// // silent errors until we decide how to handle them
	// if err != nil {
	// 	return // err
	// }

	// sometimes we want to silently drop packets
	// so this should be moved out of here.
	err = SendRADIUSPacket(r.conn, addr, responsePacket, r.Secret, true)
	if err != nil {
		log.Fatal(err)
	}

	return // nil
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
