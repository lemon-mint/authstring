# AuthString

[![GitHub](https://img.shields.io/github/license/lemon-mint/authstring?style=for-the-badge)](https://github.com/lemon-mint/authstring/blob/main/LICENSE)
[![Go Reference](https://img.shields.io/badge/go-reference-%23007d9c?style=for-the-badge&logo=go)](https://pkg.go.dev/github.com/lemon-mint/authstring)

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

[![Go Playground](https://img.shields.io/badge/go-playground-%23007d9c?style=for-the-badge&logo=go)](https://go.dev/play/p/8j05O7Hg__g?v=gotip)
