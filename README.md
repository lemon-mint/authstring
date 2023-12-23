# AuthString

Password Hashing Library

## Usage

```go
package main

import (
  "fmt"

  "github.com/lemon-mint/authstring"
)

func main() {
  hash := authstring.AuthString([]byte("password"))
  fmt.Println(hash) // Ag....

  ok, upgrade := authstring.VerifyAuthString([]byte("password"), hash)
  if !ok {
    panic("Failed to verify password")
  }

  _ = upgrade
  // if upgrade {
  //   hash = authstring.AuthString([]byte("password"))
  //   db.UpdateUserPassword("username", hash)
  // }
}
```

[Go Playground](https://go.dev/play/p/8j05O7Hg__g?v=gotip)
