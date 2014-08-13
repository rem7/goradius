package goradius

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
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

// includes VSA attributes
type RadiusAttribute struct {
	Type         uint8
	Length       uint8
	VendorId     uint32
	VendorType   uint8
	VendorLength uint8
	Value        []byte
}

type RadiusPacket struct {
	RadiusHeader
	Attributes []RadiusAttribute
	Addr       *net.UDPAddr
}

type VendorSpecificAttribute struct {
	VendorId     uint32
	VendorType   uint8
	VendorLength uint8
}

/*
 * RadiusHeader
 */

func (r RadiusHeader) String() string {
	return fmt.Sprintf("Type: '%v' Identifier: %v Length: %v Authenticator: %x",
		request_type_to_string[r.Code], r.Identifier, r.Length, r.Authenticator)
}

/*
 * RadiusAttribute
 */

func (r RadiusAttribute) Bytes() []byte {

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

func (r RadiusAttribute) String() string {
	return fmt.Sprintf("%v: %x", code_to_attributes[r.Type], r.Value)
}

/*
 * RadiusPacket
 */

func NewRadiusPacket() *RadiusPacket {
	var p RadiusPacket
	return &p

}

func (r RadiusPacket) String() string {
	return fmt.Sprintf("RadiusPacket{%v %v}", r.RadiusHeader, r.Attributes)
}

func (r *RadiusPacket) Duplicate() *RadiusPacket {

	dest := RadiusPacket{}
	dest.Code = r.Code
	dest.Identifier = r.Identifier
	dest.Length = r.Length
	dest.Authenticator = r.Authenticator

	for _, attr := range r.Attributes {
		dest.Attributes = append(dest.Attributes, attr)
	}

	return &dest
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

		vsa_attr, err := CreateVSA(attrTypeStr, value)
		if err != nil {
			return err
		}

		p.Attributes = append(p.Attributes, vsa_attr)
		err = nil

	}

	return err
}

func (p *RadiusPacket) AddAttributeByType(attrType uint8, value []byte) {

	attr := RadiusAttribute{
		Type:  attrType,
		Value: value,
	}

	p.Attributes = append(p.Attributes, attr)

}

func (p *RadiusPacket) GetAttribute(attrType string) [][]byte {

	var attrs [][]byte

	if attrTypeCode, ok := attributes_to_code[attrType]; ok {
		for _, v := range p.Attributes {

			if v.Type == attrTypeCode {

				// if v.Type == VendorSpecific {
				// 	reader := bytes.NewBuffer(v.Value)
				// 	vsa := VendorSpecificAttribute{}
				// 	err := binary.Read(reader, binary.BigEndian, &vsa)
				// 	if err != nil {
				// 		log.Fatal(err)
				// 	}
				// 	value := reader.Next(int(vsa.VendorLength))
				// 	attrs = append(attrs, value)
				// } else {
				// }
				attrs = append(attrs, v.Value)

			}

		}
	} else {
		log.Printf("Looking for VSA")
		vsa, err := FindVSA(attrType)
		if err == nil {
			for _, v := range p.Attributes {
				if v.Type == VendorSpecific {
					if vsa.VendorId == v.VendorId && vsa.VendorType == v.VendorType {
						attrs = append(attrs, v.Value)
					}
				}
			}
		}
	}

	return attrs
}

func (p *RadiusPacket) GetFirstAttribute(attrType string) []byte {

	var attr []byte
	attrs := p.GetAttribute(attrType)
	if len(attrs) > 0 {
		attr = attrs[0]
	}

	return attr
}

func (p *RadiusPacket) GetFirstAttributeAsString(attrType string) string {
	return string(p.GetFirstAttribute(attrType))
}

func encodeVendorSpecificAttr(attr RadiusAttribute) []byte {

	vsa := VendorSpecificAttribute{
		VendorId:     attr.VendorId,
		VendorType:   attr.VendorType,
		VendorLength: uint8(len(attr.Value) + 2),
	}

	buf := bytes.NewBuffer([]byte{})
	err := binary.Write(buf, binary.BigEndian, vsa)
	if err != nil {
		panic(err)
	}

	err = binary.Write(buf, binary.BigEndian, attr.Value)
	if err != nil {
		panic(err)
	}

	return buf.Bytes()

}

func VendorAttribute(attrName string, value []byte) RadiusAttribute {

	attr, err := CreateVSA(attrName, value)
	if err != nil {
		log.Fatal(err)
	}

	return attr

}

func CreateVSA(attrName string, value []byte) (RadiusAttribute, error) {

	vsa, err := FindVSA(attrName)
	if err != nil {
		return RadiusAttribute{}, err
	}

	rattr := RadiusAttribute{
		Type:       uint8(26),
		VendorId:   vsa.VendorId,
		VendorType: vsa.VendorType,
		Value:      value,
	}

	rattr.Length = uint8(2 + len(rattr.Value))

	return rattr, nil

}

func (r *RadiusPacket) encodeAttrs(secret string) []byte {

	buf := bytes.NewBuffer([]byte{})

	for _, attr := range r.Attributes {

		encoded_ok := true
		switch attr.Type {
		case UserPassword:
			// We usually wanna decode the password because if we proxy it
			// we will need to re-encode with the new secret  anyways
			password_data := xorPassword(secret, r.Authenticator, attr.Value, false)
			attr.Length = uint8(len(password_data))
			attr.Value = password_data[:]
		case VendorSpecific:
			vendor_data := encodeVendorSpecificAttr(attr)
			attr.Length = uint8(len(vendor_data) + 2)
			attr.Value = vendor_data[:]
		default:
			attr.Length = uint8(len(attr.Value))
		}

		if encoded_ok {
			buf.Write(attr.Bytes())
		}
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
		packet.Attributes = append(packet.Attributes, attr)
	}

	return packet, nil

}

func parseAttributes(data []byte, requestAuthenticator [16]byte, secret string) []RadiusAttribute {

	var attrs []RadiusAttribute
	reader := bytes.NewBuffer(data)

	for {

		var err error
		attr := RadiusAttribute{}

		ok := false

		attr.Type, err = reader.ReadByte()
		if err == io.EOF {
			break
		}

		attr.Length, err = reader.ReadByte()
		if err == io.EOF {
			break
		}

		switch attr.Type {
		case uint8(0):
			log.Printf("attr_type 0?")
		case uint8(UserPassword):
			val := reader.Next(int(attr.Length) - 2)
			attr.Value = xorPassword(secret, requestAuthenticator, val, true)
			ok = true
		case uint8(VendorSpecific):

			vsa := VendorSpecificAttribute{}
			err = binary.Read(reader, binary.BigEndian, &vsa)
			if err != nil {
				log.Fatal(err)
			}

			attr.VendorId = vsa.VendorId
			attr.VendorType = vsa.VendorType
			attr.VendorLength = vsa.VendorLength
			attr.Value = reader.Next(int(vsa.VendorLength - 2))
			ok = true

			// log.Printf("praseAttrs: %+v", vsa)
			// log.Printf("VSA: %+v", vsa)
			// log.Printf("Value: %v", attr.Value)
			// log.Printf("Value hex: %x", attr.Value)
		default:
			attr.Value = reader.Next(int(attr.Length) - 2)
			ok = true
		}

		if ok {
			attrs = append(attrs, attr)
		}

	}

	return attrs
}

func GenerateRandomAuthenticator() [16]byte {

	authenticator := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := rand.Read(authenticator[:])
	if err != nil {
		panic(err)
	}

	return authenticator
}

func paddAttr(data []byte, size int) []byte {

	padded := make([]byte, size)
	for i, b := range data {
		padded[i] = b
	}
	return padded

}

func xorPassword(secret string, authenticator [16]byte, password []byte, decrypt bool) []byte {

	padding := 16
	fields := 1
	for {
		res := fields * 16
		if res >= len(password) {
			padding = res
			break
		}
		fields += 1
	}

	paddedPassword := paddAttr(password, padding)
	second_one_way_hash := authenticator
	var password_out []byte

	for i := 0; i < padding; i = i + 16 {

		xored := make([]byte, 16)
		newHash := md5.New()
		newHash.Write([]byte(secret))
		newHash.Write(second_one_way_hash[:])
		newHashSum := newHash.Sum(nil)

		for j := 0; j < 16; j++ {
			xored[j] = paddedPassword[i+j] ^ newHashSum[j]

			if xored[j] == 0x00 {
				break
			}
		}

		if decrypt {
			copy(second_one_way_hash[:], paddedPassword[i:i+16])
		} else {
			copy(second_one_way_hash[:], xored[:])
		}

		password_out = append(password_out, xored...)

	}

	return password_out
}
