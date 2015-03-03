package main

import (
	"flag"
	"github.com/amdonov/lite-idp/server"
	"log"
)

func main() {
	flag.Parse()

	server, err := server.New()
	if err != nil {
		log.Fatal("Failed to configure server.", err)
	}
	server.Start()
	if err := server.Start(); err != nil {
		log.Fatal("Failed to start server.", err)
	}
}
