// Copyright 2026 Andrew Lapham
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package teradata

import (
	"context"
	"crypto/tls"
	"database/sql/driver"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
)

type teradataConnector struct {
	config        *Config
	discoveredIps []string
}

func newConnector(config *Config) *teradataConnector {
	config.normalize()
	return &teradataConnector{
		config: config,
	}
}

func (c *teradataConnector) Connect(ctx context.Context) (driver.Conn, error) {
	return c.connect(ctx, false)
}

func (c *teradataConnector) connect(ctx context.Context, tlsFallback bool) (driver.Conn, error) {
	var err error

	// On first connect we run COP discovery / IP Lookup
	if len(c.discoveredIps) == 0 {
		c.discoveredIps = make([]string, 0)
		if c.config.CopMode {
			err = c.copDiscovery()
			if err != nil {
				return nil, wrapConnectionError(err)
			}
		} else {
			ips, err := net.LookupHost(c.config.Host)
			if err != nil {
				return nil, errors.New("unable to find host")
			}
			c.discoveredIps = append(c.discoveredIps, ips...)
		}
	}

	if len(c.discoveredIps) == 0 {
		return nil, errors.New("unable to find IP address for host")
	}

	// Rotate - Randomly pick a starting point for each new connection:
	disIpCount := len(c.discoveredIps)
	rotateIndex := 0
	if disIpCount > 1 {
		rotateIndex = rand.IntN(disIpCount)
	}

	conn := &teradataConnection{
		config:    c.config,
		requestNo: 0,
	}
	dialContext := ctx
	if c.config.Timeout > 0 {
		var cancel context.CancelFunc
		dialContext, cancel = context.WithTimeout(ctx, c.config.Timeout)
		defer cancel()
	}

	var ipPort string
	var port = c.config.Port
	var lastErr error
	var usingTlsPort = false
	// TODO: If tls mode = ALLOW and plaintext is not allowed then we should upgrade to tls
	if c.config.useTls() && !tlsFallback {
		port = c.config.SSLPort
		usingTlsPort = true
	}

	// Try each disoverted IP to establish the connection:
	startIndex := rotateIndex
	for {
		ipAddr := c.discoveredIps[rotateIndex]
		ipPort = fmt.Sprintf("%s:%d", ipAddr, port)
		c.config.Logger.Log(context.Background(), logLevelTrace, "connect", "ipPort", ipPort)
		dialer := net.Dialer{Timeout: c.config.Timeout}
		conn.netConn, err = dialer.DialContext(dialContext, "tcp", ipPort)
		if err != nil {
			lastErr = err
			rotateIndex = (rotateIndex + 1) % disIpCount
			if rotateIndex == startIndex {
				break
			}
			continue
		}
		lastErr = nil
		conn.remoteHost = ipAddr
		conn.remotePort = port
		break
	}

	// We tried all COPs and couldn't get a connection:
	if lastErr != nil {
		if usingTlsPort && c.config.allowTlsFallback() {
			return c.connect(ctx, true)
		}
		return nil, wrapConnectionError(lastErr)
	}

	conn.rawConn = conn.netConn
	conn.buffer = newReadBuffer()
	conn.writeBuffer = newWriteBuffer()

	// Try to upgrage connection:
	if c.config.useTls() && !tlsFallback {
		c.config.Logger.Log(context.Background(), logLevelTrace, "Attempting TLS Handshake")
		tlsClient := tls.Client(conn.rawConn, c.config.tlsConfig())
		err = tlsClient.Handshake()
		if err != nil {
			c.config.Logger.Log(context.Background(), logLevelTrace, "TLS Connect", "error", err.Error())
			if c.config.allowTlsFallback() {
				conn.rawConn.Close()
				return c.connect(ctx, true)
			}
			return nil, wrapConnectionError(err) //TODO Fallback to 1025
		}
		c.config.Logger.Log(context.Background(), logLevelTrace, "TLS Connect OK")
		conn.netConn = tlsClient

		// WS Upgrade
		err = conn.upgradeWebSocket()
		if err != nil {
			if c.config.allowTlsFallback() {
				conn.rawConn.Close()
				conn.netConn.Close()
				return c.connect(ctx, true)
			}
			return nil, wrapConnectionError(err) //TODO Fallback to 1025
		}
		conn.isTlsConn = true
		c.config.Logger.Log(context.Background(), logLevelTrace, "WebSocket Upgrade OK")
	}

	if conn.netConn == nil {
		return nil, fmt.Errorf("unable to connect to host, last attempted: %s", ipPort)
	}

	if tc, ok := conn.netConn.(*net.TCPConn); ok {
		if err := tc.SetKeepAlive(true); err != nil {
			c.config.Logger.Log(context.Background(), logLevelTrace, "Keepalive", "error", err)
		}
	}

	if ok, err := conn.handshake(); !ok || err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *teradataConnector) copDiscovery() error {
	var (
		copPrefix     = c.config.Host
		copSuffix     = ""
		copNumber     = 1
		lastCopIpAddr = ""
	)
	front, end, found := strings.Cut(c.config.Host, ".")
	if found {
		copPrefix = front
		copSuffix = end
	}

	if c.config.CopLast {
		lastCopHost := fmt.Sprintf("%scoplast.%s", copPrefix, copSuffix)
		ips, err := net.LookupHost(lastCopHost)
		if err == nil && len(ips) > 0 {
			lastCopIpAddr = ips[0]
		}
	}

	// Check HostCop1...HostCopN to find all hosts:
	for {
		copHost := fmt.Sprintf("%scop%d.%s", copPrefix, copNumber, copSuffix)
		ips, err := net.LookupHost(copHost)
		if err != nil || len(ips) == 0 {
			break
		}
		if lastCopIpAddr != "" && ips[0] == lastCopIpAddr {
			// found last
			break
		}
		c.discoveredIps = append(c.discoveredIps, ips...)
		copNumber += 1
	}

	if len(c.discoveredIps) == 0 {
		// No cops found fallback to direct host
		ips, err := net.LookupHost(c.config.Host)
		if err != nil {
			return errors.New("unable to find host")
		}
		c.discoveredIps = append(c.discoveredIps, ips...)
	}

	return nil
}

func (c *teradataConnector) Driver() driver.Driver {
	return &TeradataDriver{}
}
