# llib - [nbio](https://github.com/lesismal/nbio)'s dependency lib.

[![GoDoc][1]][2] [![MIT licensed][3]][4] [![Go Version][5]][6]

[1]: https://godoc.org/github.com/lesismal/llib?status.svg
[2]: https://godoc.org/github.com/lesismal/llib
[3]: https://img.shields.io/badge/license-BSD-blue.svg
[4]: LICENSE
[5]: https://img.shields.io/badge/go-%3E%3D1.16-30dff3?style=flat-square&logo=go
[6]: https://github.com/lesismal/llib


## Features
- [x] Blocking/NonBlocking TLS interface(rewritten from a copy of golang 1.6 std's tls).


## Why this lib?
- [nbio](https://github.com/lesismal/nbio) itself depends on the golang std and llib only and keeps the dependencies clean.
- If new features of [nbio](https://github.com/lesismal/nbio) needs to depend on 3rd libs, it will be implemented in llib too.
