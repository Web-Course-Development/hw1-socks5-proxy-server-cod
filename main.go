// HW1_213912215_325424927
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {

	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		log.Printf("Accepted connection from: %v", conn.RemoteAddr())
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}

	nMethods := header[1]
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	requiredMethod := byte(0x00)
	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if expectedUser != "" {
		requiredMethod = 0x02
	}

	methodSupported := false
	for _, m := range methods {
		if m == requiredMethod {
			methodSupported = true
			break
		}
	}

	if !methodSupported {
		conn.Write([]byte{0x05, 0xFF})
		return
	}
	conn.Write([]byte{0x05, requiredMethod})

	if requiredMethod == 0x02 {
		authHeader := make([]byte, 2)
		if _, err := io.ReadFull(conn, authHeader); err != nil {
			return
		}
		if authHeader[0] != 0x01 {
			return
		}

		uLen := authHeader[1]
		uName := make([]byte, uLen)
		if _, err := io.ReadFull(conn, uName); err != nil {
			return
		}

		pLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, pLenBuf); err != nil {
			return
		}
		pLen := pLenBuf[0]

		passwd := make([]byte, pLen)
		if _, err := io.ReadFull(conn, passwd); err != nil {
			return
		}

		if string(uName) == expectedUser && string(passwd) == expectedPass {
			conn.Write([]byte{0x01, 0x00})
		} else {
			conn.Write([]byte{0x01, 0x01})
			return
		}
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}

	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atyp := reqHeader[3]
	var targetAddr string

	if atyp == 0x01 {

		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return
		}
		targetAddr = net.IP(ipBuf).String()
	} else if atyp == 0x03 {

		domainLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, domainLenBuf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		targetAddr = string(domainBuf)
	} else {

		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	targetPort := binary.BigEndian.Uint16(portBuf)

	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

	log.Printf("Forwarding traffic to: %s", target)

	destConn, err := net.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Connection refused
		return
	}
	defer destConn.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(conn, destConn)
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(destConn, conn)
		if tcpConn, ok := destConn.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}
