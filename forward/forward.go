package forward

import (
	"fmt"
	"net"
)

func Transfer(src *net.TCPAddr) (dest *net.TCPAddr) {
	// 本地地址访问转发
	if net.ParseIP("127.0.0.1").Equal(src.IP) {
		fmt.Println("开启转发")
		return &net.TCPAddr{
			IP:   net.ParseIP("172.17.88.204"),
			Port: src.Port,
		}
	}

	return src
}
