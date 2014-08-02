package goradius

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strings"
)

var (
	HEADER_SIZE = 20
)

type RadiusHeader struct {
	Code          uint8
	Identifier    uint8
	Length        uint16
	Authenticator [authenticatorLength]byte
}

type RadiusAttribute struct {
	Type   uint8
	Length uint8
	Value  []byte
}

type RadiusPacket struct {
	RadiusHeader
	Attributes []RadiusAttribute
	Addr       *net.UDPAddr
}

func NewRadiusPacket() *RadiusPacket {
	var p RadiusPacket
	// p.Attributes = make(map[string][]byte)
	return &p

}

func (p *RadiusPacket) AddAttribute(attrTypeStr string, value []byte) error {

	var err error
	if attrTypeCode, ok := attributes_to_code[attrTypeStr]; ok {
		attr := RadiusAttribute{
			Type:  attrTypeCode,
			Value: value,
		}

		p.Attributes = append(p.Attributes, attr)
		err = nil
	} else {
		err = errors.New("Attribute not found")
	}

	return err
}

func (p *RadiusPacket) GetAttribute(attrType string) [][]byte {

	var attrs [][]byte

	if attrTypeCode, ok := attributes_to_code[attrType]; ok {
		for _, v := range p.Attributes {

			if v.Type == attrTypeCode {
				attrs = append(attrs, v.Value)
			}

		}
	}

	return attrs
}

func (p *RadiusPacket) GetFirstAttributeAsString(attrType string) string {

	attr := ""

	if attrTypeCode, ok := attributes_to_code[attrType]; ok {
		for _, v := range p.Attributes {
			if v.Type == attrTypeCode {
				attr = string(v.Value)
				break
			}
		}
	}

	return attr
}

func (r *RadiusPacket) encodeAttrs(secret string) []byte {

	buf := bytes.NewBuffer([]byte{})

	for _, attr := range r.Attributes {

		if attr.Type == 2 {
			password_data := encryptPassword(secret, r.Authenticator, attr.Value)
			attr.Length = uint8(len(password_data))
			attr.Value = password_data[:]
		} else {
			attr.Length = uint8(len(attr.Value))
		}

		buf.Write(attr.Bytes())
	}

	return buf.Bytes()
}

func (r *RadiusAttribute) Bytes() []byte {

	buf := bytes.NewBuffer([]byte{})

	err := binary.Write(buf, binary.BigEndian, &r.Type)
	if err != nil {
		log.Fatal(err)
	}

	r.Length = uint8(len(r.Value) + 2)
	err = binary.Write(buf, binary.BigEndian, &r.Length)
	if err != nil {
		log.Fatal(err)
	}

	err = binary.Write(buf, binary.BigEndian, r.Value[:])
	if err != nil {
		log.Fatal(err)
	}

	return buf.Bytes()

}

func (r *RadiusPacket) EncodePacket(secret string) ([]byte, error) {

	// encode all attrs first
	attrs_data := r.encodeAttrs(secret)
	attrs_size := len(attrs_data)
	r.Length = uint16(attrs_size + HEADER_SIZE)

	buf := bytes.NewBuffer([]byte{})

	err := binary.Write(buf, binary.BigEndian, &r.RadiusHeader)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, attrs_data)

	return buf.Bytes(), err

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
		name := code_to_attributes[attr.Type]
		packet.AddAttribute(name, attr.Value)
	}

	return packet, nil

}

func parseAttributes(data []byte, requestAuthenticator [16]byte, secret string) []RadiusAttribute {

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
			log.Printf("attr_type == 0?")
			break
		}

		// If there is a password we should decrypt it
		if attr_type == 2 {
			value = decryptPassword(secret, value, requestAuthenticator)
		}

		attr := RadiusAttribute{
			Type:   attr_type,
			Length: length,
			Value:  value,
		}
		attrs = append(attrs, attr)

	}

	return attrs
}

func GenerateRandomAuthenticator() [16]byte {

	b := make([]byte, 16)
	n, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	if n != 16 {
		log.Fatalf("Could not generate just 16 bytes")
	}

	var ret [16]byte
	copy(ret[:], b[:16])
	return ret
}

func paddAttr(data []byte, size int) []byte {
	padded := make([]byte, size)
	for i, b := range data {
		padded[i] = b
	}
	return padded
}

func encryptPassword(secret string, authenticator [16]byte, password []byte) [16]byte {

	paddedPassword := paddAttr(password, 16)

	_b := md5.New()
	_b.Write([]byte(secret))
	_b.Write(authenticator[:])
	b := _b.Sum(nil)

	xored := [16]byte{}

	for i := 0; i < 16; i++ {
		xored[i] = paddedPassword[i] ^ b[i]
	}

	return xored
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
