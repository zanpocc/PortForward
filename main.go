package main

import (
	"fmt"
	"io"
	"net"
	"port_forward/forward"
	"port_forward/socks5"
	"sync"
)

func main() {

	l, err := net.Listen("tcp", ":1080")
	if err != nil {
		panic("listen localhost port error")
	}

	for {
		c, err := l.Accept()
		if err != nil {
			panic("recv connection error")
		}

		fmt.Println("接收到客户端连接")

		go func() {
			defer c.Close()

			buff := make([]byte, 255)
			n, err := c.Read(buff)
			if err != nil {
				panic("read data error")
			}

			// 与客户端进行握手
			resp, err := socks5.HandleHandshake(buff[0:n])
			if err != nil {
				fmt.Println("解析客户端握手数据失败")
				panic(err)
			}

			_, err = c.Write(resp)
			if err != nil {
				fmt.Println("向客户端发送握手数据失败")
				panic(err)
			}

			// 获取客户端代理请求
			n, err = c.Read(buff)
			if err != nil {
				fmt.Println("读取客户端请求数据失败")
				panic(err)
			}

			var request socks5.Socks5Resolution
			resp, err = request.LSTRequest(buff[0:n])
			if err != nil {
				fmt.Println("解析客户端代理请求数据失败")
				panic(err)
			}

			_, err = c.Write(resp)
			if err != nil {
				fmt.Println("写入客户端代理请求数据响应失败")
				panic(err)
			}

			fmt.Println(request.RAWADDR.IP, request.RAWADDR.Port)
			// fmt.Println(c.RemoteAddr(), request.DSTDOMAIN, request.DSTADDR, request.DSTPORT)
			// 配置端口转发规则
			forwardAddr := forward.Transfer(request.RAWADDR)

			// 连接真正的远程服务
			remoteServer, err := net.DialTCP("tcp", nil, forwardAddr)
			if err != nil {
				fmt.Println(c.RemoteAddr(), err)
				return
			}

			defer remoteServer.Close()

			wg := new(sync.WaitGroup)
			wg.Add(2)

			// 本地的内容copy到远程端
			go func() {
				defer wg.Done()
				io.Copy(remoteServer, c)
			}()

			// 服务端的内容copy到本地
			go func() {
				defer wg.Done()
				io.Copy(c, remoteServer)
			}()

			wg.Wait()
		}()
	}
}
