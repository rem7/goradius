
# goradius
A simple implementation of a RADIUS server in go.

### TODO
* Handle vendor specific attributes
* Handle passwords > 16 chars

### Example

```go
package main

import (
    "bytes"
    "github.com/rem7/goradius"
    "log"
)

// // echo "User-Name=steve,User-Password=testing" | radclient -sx 127.0.0.1:1812 auth secret

func passwordCheck(req, res *goradius.RadiusPacket) error {

    username := req.GetAttribute("User-Name")
    usernameData, _ := username.([]byte)

    password := req.GetAttribute("User-Password")
    passwordData, _ := password.([]byte)

    if bytes.Equal(passwordData, []byte("testing")) &&
        bytes.Equal(usernameData, []byte("steve")) {
        res.Code = 2

        res.AddAttribute("NAS-Identifier", []byte("rem7"))
        res.AddAttribute("Idle-Timeout", uint32(600))
        res.AddAttribute("Session-Timeout", uint32(10800))
    } else {
        res.Code = 3
    }

    return nil

}

func main() {

    log.Printf("Server started")
    server := goradius.RadiusServer{}
    server.Secret = "s3cr37"
    server.Handler(passwordCheck)
    log.Fatal(server.ListenAndServe("0.0.0.0:1812"))

}
```