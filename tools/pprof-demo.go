package main

import (
    "log"
    "net/http"
    _ "net/http/pprof"
)

func main() {
    log.Println("pprof 服务启动在 :6060")
    http.ListenAndServe(":6060", nil)
}
