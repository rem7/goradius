package goradius

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"strings"
)

type RadiusRawAttribute struct {
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
	Attributes map[string]interface{}
}

func NewRadiusPacket() *RadiusPacket {
	var p RadiusPacket
	p.Attributes = make(map[string]interface{})
	return &p

}

func (p *RadiusPacket) AddAttribute(attrType string, value interface{}) error {

	p.Attributes[attrType] = value

	return nil
}

func (r *RadiusPacket) GenerateAuthenticator() {

	for i := range r.RadiusHeader.Authenticator {
		r.RadiusHeader.Authenticator[i] = byte(rand.Int())
	}
}

func (r *RadiusPacket) GenerateId() {
	r.RadiusHeader.Identifier = uint8(rand.Int() % 256)
}

func (p *RadiusPacket) GetAttribute(attrType string) interface{} {

	return p.Attributes[attrType]

}

func EncodeRADIUSPacket(packet *RadiusPacket, secret string, recalculateAuthenticator bool) ([]byte, error) {

	newBuf := bytes.NewBuffer([]byte{})
	binary.Write(newBuf, binary.BigEndian, &packet.RadiusHeader)

	// Write in all the attributes
	for attrName, attrValue := range packet.Attributes {
		rawAttr := RadiusRawAttribute{}

		rawAttr.TypeValue = attributes_to_code[attrName]
		if rawAttr.TypeValue == 26 {
			// TODO: handle vendor specific
			rawAttr.TypeValue = 26
		}

		err := binary.Write(newBuf, binary.BigEndian, &rawAttr.TypeValue)
		if err != nil {
			log.Printf("Failed to write!")
			return nil, err
		}

		// Dirty. I don't know how I feel about this.
		switch t := attrValue.(type) {
		default:
			log.Printf("unexpected type %T", t)
		case uint32:
			rawAttr.Length = 4 + 2
			err = binary.Write(newBuf, binary.BigEndian, &rawAttr.Length)
			checkErr("err 1", err)
			err = binary.Write(newBuf, binary.BigEndian, t)
			checkErr("err 2", err)
		case []byte:
			rawAttr.Length = uint8(len(t)) + 2
			err = binary.Write(newBuf, binary.BigEndian, &rawAttr.Length)
			checkErr("err 3", err)
			err = binary.Write(newBuf, binary.BigEndian, t)
			checkErr("err 4", err)
		}
	}

	output := newBuf.Bytes()
	packet.RadiusHeader.Length = uint16(len(output))

	// Now that we have written all the attributes
	// we know the size and we can override it.
	currentSize := len(output)
	var h, l uint8 = uint8(uint16(currentSize) >> 8), uint8(uint16(currentSize) & 0xff)
	packet.Length = uint16(currentSize)
	output[2] = h
	output[3] = l

	// Calculate the md5 with the previous authenticator
	// and the current secret.
	// chicken and egg... what?
	if recalculateAuthenticator {
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

	return output, nil

}

func ParseRADIUSPacket(rawMsg []byte, secret string) (*RadiusPacket, error) {

	packet := NewRadiusPacket()
	reader := bytes.NewReader(rawMsg)

	err := binary.Read(reader, binary.BigEndian, &packet.RadiusHeader)
	if err != nil {
		return nil, err
	}

	rawAttributesBytes := rawMsg[headerEnd:]

	rawAttributes := parseAttributes(rawAttributesBytes, packet.Authenticator, secret)

	for _, attr := range rawAttributes {
		name := code_to_attributes[attr.TypeValue]
		packet.AddAttribute(name, attr.Value)
	}

	return packet, nil

}

func parseAttributes(data []byte, requestAuthenticator [16]byte, secret string) []RadiusRawAttribute {

	var attrs []RadiusRawAttribute
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

		// If there is a password we should decrypt it
		if attr_type == 2 {
			value = decryptPassword(secret, value, requestAuthenticator)
		}

		attr := RadiusRawAttribute{
			TypeValue: attr_type,
			Length:    length,
			Value:     value,
		}
		attrs = append(attrs, attr)

	}

	return attrs
}

func decryptPassword(secret string, value []byte, requestAuthenticator [16]byte) []byte {

	// TODO: Allow passwords longer than 16 characters...
	var bufr [16]byte

	S := []byte(secret)
	c := requestAuthenticator[0:16]

	_b := md5.New()
	_b.Write(S)
	_b.Write(c)
	b := _b.Sum(nil)

	for i, p := range value {
		bufr[i] = b[i] ^ p
	}

	idx := strings.Index(string(bufr[0:16]), "\x00")
	ret := bufr[0:16]
	if idx > 0 {
		ret = bufr[:idx]
	}
	return ret
}
