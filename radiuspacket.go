package goradius

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

func (p *RadiusPacket) GetAttribute(attrType string) interface{} {

	return p.Attributes[attrType]

}
