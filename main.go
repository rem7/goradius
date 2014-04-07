package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
)

// // echo "User-Name=steve,User-Password=testing" | radclient -sx 127.0.0.1:1812 auth secret

const (
	headerEnd           = 20
	authenticatorLength = 16
)

type RadiusAttribute struct {
	TypeValue uint8
	Length    uint8
	Value     []byte
}

type RadiusHeader struct {
	Code          uint8
	Identifier    uint8
	Length        uint16
	Authenticator [authenticatorLength]byte
}

type RadiusPacket struct {
	RadiusHeader
	Attributes []RadiusAttribute
}

func main() {

	log.Printf("Server started")
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:1812")
	if err != nil {
		log.Fatalln(err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalln(err)
	}

	for {

		e := handleConn(conn)
		if e != nil {
			// ignore errors.
			log.Printf("WARNING: %v", e.Error())
		}

	}

}

func handleConn(conn *net.UDPConn) error {

	bufr := make([]byte, 4096)
	rawMsgSize, addr, err := conn.ReadFromUDP(bufr)
	if err != nil {
		panic(err)
	}

	if rawMsgSize < 20 {
		return errors.New("Message to short.")
	}

	rawMsg := bufr[0:rawMsgSize]
	radiusPacket, err := parseRADIUSPacket(rawMsg)

	responsePacket := RadiusPacket{}
	responsePacket.RadiusHeader = radiusPacket.RadiusHeader
	responsePacket.Code = 2

	output, err := encodeRadiusPacket(&responsePacket, "secret")
	if err != nil {
		return err
	}

	bytesWritten, err := conn.WriteToUDP(output, addr)
	if bytesWritten != int(responsePacket.Length) {
		log.Printf("WARNING: Written bytes in UDP socket did not match packet size. Packet: %v Written: %v",
			responsePacket.Length, bytesWritten)
	}

	if err != nil {
		return err
	}

	return nil
}

func encodeRadiusPacket(packet *RadiusPacket, secret string) ([]byte, error) {

	newBuf := bytes.NewBuffer([]byte{})
	binary.Write(newBuf, binary.BigEndian, &packet.RadiusHeader)

	// TODO
	// This is a dumb implementation.
	// Radius Attributes need to be added :)
	// and packet length re-calculated.
	responsePacket.Length = 20

	output := newBuf.Bytes()

	// Calculate the md5 with the previous authenticator
	// and the current secret.
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

	return output, nil

}

func parseRADIUSPacket(rawMsg []byte) (*RadiusPacket, error) {

	packet := RadiusPacket{}
	reader := bytes.NewReader(rawMsg)

	err := binary.Read(reader, binary.BigEndian, &packet.RadiusHeader)
	if err != nil {
		return nil, err
	}

	rawAttributes := rawMsg[headerEnd:]
	packet.Attributes = parseAttributes(rawAttributes)

	return &packet, nil

}

func parseAttributes(data []byte) []RadiusAttribute {

	var attrs []RadiusAttribute
	reader := bytes.NewBuffer(data)

	for {

		var e error
		var attr_type uint8
		var length uint8

		attr_type, e = reader.ReadByte()
		if e == io.EOF {
			break
		}

		length, e = reader.ReadByte()
		if e == io.EOF {
			break
		}

		value := reader.Next(int(length) - 2)

		if attr_type == 0 {
			break
		}

		// TODO: If there is a password we should decrypt it

		attr := RadiusAttribute{
			TypeValue: attr_type,
			Length:    length,
			Value:     value,
		}
		attrs = append(attrs, attr)

	}

	return attrs
}
