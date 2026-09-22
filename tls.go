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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	sslModeVerifyFull string = "VERIFY-FULL"
	sslModeVerifyCA   string = "VERIFY-CA"
	sslModeRequire    string = "REQUIRE"
	sslModePrefer     string = "PREFER"
	sslModeAllow      string = "ALLOW"
	sslModeDisable    string = "DISABLE"
)

const (
	sslLevelDisable int = iota
	sslLevelAllow
	sslLevelPrefer
	sslLevelRequire
	sslLevelVerifyCA
	sslLevelVerifyFull
)

func decodeSslMode(mode string) int {
	switch mode {
	case sslModeVerifyFull:
		return sslLevelVerifyFull
	case sslModeVerifyCA:
		return sslLevelVerifyCA
	case sslModeRequire:
		return sslLevelRequire
	case sslModePrefer:
		return sslLevelPrefer
	case sslModeAllow:
		return sslLevelAllow
	case sslModeDisable:
		return sslLevelDisable
	}
	return sslLevelPrefer
}

func (c *Config) tlsConfig() *tls.Config {
	// TODO
	return &tls.Config{
		ServerName:            c.SSLServerName,
		MinVersion:            tls.VersionTLS12,
		MaxVersion:            tls.VersionTLS13,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: c.getVerifyCertFn(),
	}
}

func (c *Config) getVerifyCertFn() func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	// Create Cert Pool:
	certPool := c.getCertPool()
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrInternal
		}
		intermediates := x509.NewCertPool()
		var leaf *x509.Certificate
		for i, raw := range rawCerts {
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			if i == 0 {
				leaf = cert
			} else {
				intermediates.AddCert(cert)
			}
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         certPool,
			Intermediates: intermediates,
		})
		chainOk := err == nil
		hostOk := leaf.VerifyHostname(c.SSLServerName) == nil // TODO: Add IP check

		c.Logger.Log(context.Background(), logLevelTrace, fmt.Sprintf("TLS Verify: Chain: %t, Host: %t", chainOk, hostOk))
		switch c.SSLMode {
		case sslModeVerifyFull:
			if !chainOk {
				return ErrTlsCaFail
			}
			if !hostOk {
				return ErrTlsHostFail
			}
		case sslModeVerifyCA:
			if !chainOk {
				return ErrTlsCaFail
			}
		}

		// Ignore errors in other modes

		return nil
	}
}

func (c *Config) getCertPool() *x509.CertPool {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}
	if c.SSLBase64 != "" {
		certBytes, err := base64.URLEncoding.DecodeString(c.SSLBase64)
		if err != nil {
			c.Logger.ErrorContext(context.Background(), "error decoding SSLBase64", "error", err.Error())
		} else if ok := certPool.AppendCertsFromPEM(certBytes); !ok {
			if ders, err := x509.ParseCertificates(certBytes); err == nil {
				for _, c := range ders {
					certPool.AddCert(c)
				}
			} else {
				c.Logger.ErrorContext(context.Background(), "SSLBase64: could not parse as PEM or DER")
			}
		}
	}
	if c.SSLCA != "" {
		pemFileBytes, err := os.ReadFile(c.SSLCA)
		if err != nil {
			c.Logger.ErrorContext(context.Background(), "error reading SSLCA file", "error", err.Error())
		} else {
			certPool.AppendCertsFromPEM(pemFileBytes)
		}
	}
	if c.SSLCAPath != "" {
		files, err := filepath.Glob(filepath.Join(c.SSLCAPath, "*.pem"))
		if err != nil {
			c.Logger.ErrorContext(context.Background(), "error globbing SSLCAPath directory", "error", err.Error())
		} else {
			for _, f := range files {
				pemFileBytes, err := os.ReadFile(f)
				if err != nil {
					c.Logger.ErrorContext(context.Background(), "error reading PEM file", "error", err.Error())
				} else {
					certPool.AppendCertsFromPEM(pemFileBytes)
				}
			}
		}
	}
	return certPool
}

func (c *teradataConnection) upgradeWebSocket() error {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return ErrTlsUpgradeFail
	}

	key := base64.StdEncoding.EncodeToString(token)
	req := "GET /gateway HTTP/1.1\r\n" +
		"Host: " + c.remoteHost + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	if _, err := c.netConn.Write([]byte(req)); err != nil {
		return ErrTlsUpgradeFail
	}

	buff := c.writeBuffer.take(256)
	len, err := c.netConn.Read(buff)
	if err != nil {
		return ErrTlsUpgradeFail
	}
	reader := newBufferReader(buff, 0, len)
	respString := reader.asciiString(len)
	lines := strings.Split(respString, "\r\n")
	if slices.Contains(lines, "HTTP/1.1 101 Switching Protocols") && slices.Contains(lines, "Upgrade: websocket") {
		return nil
	}
	return ErrTlsUpgradeFail
}

func (c *teradataConnection) getWsFrameLength(packetLen int) int {
	if !c.isTlsConn {
		return 0
	}
	switch {
	case packetLen <= 125:
		return 2
	case packetLen <= 65535:
		return 4
	}
	return 10
}

func (c *teradataConnection) writeWsFrameHeader(writer *bufferWriter, packetLen int) (int, error) {
	if !c.isTlsConn {
		return 0, nil
	}
	switch {
	case packetLen <= 125:
		writer.byte(0x82)
		writer.byte(byte(packetLen))
		return 2, nil
	case packetLen <= 65535:
		writer.byte(0x82)
		writer.byte(126)
		writer.byte(byte(packetLen >> 8))
		writer.byte(byte(packetLen))
		return 4, nil
	default:
		writer.byte(0x82)
		writer.byte(127)
		writer.bytes([]byte{0, 0, 0, 0})
		writer.byte(byte(packetLen >> 24))
		writer.byte(byte(packetLen >> 16))
		writer.byte(byte(packetLen >> 8))
		writer.byte(byte(packetLen))
		return 10, nil

	}
}

func (c *teradataConnection) readWsFrameHeader() (uint64, error) {
	wshdr, err := c.readNext(2)
	if err != nil {
		return 0, err
	}
	fin := wshdr[0]&0x80 != 0
	opcode := wshdr[0] & 0x0F
	if !fin || opcode != 0x02 {
		return 0, fmt.Errorf("teradatasql: unexpected websocket frame: fin=%v opcode=%d", fin, opcode)
	}
	//masked := wshdr[1]&0x80 != 0
	len := uint64(wshdr[1] & 0x7F)
	switch len {
	case 126:
		if data, err := c.readNext(2); err == nil {
			return uint64(data[0])<<8 | uint64(data[1]), nil
		} else {
			return 0, err
		}
	case 127:
		if data, err := c.readNext(8); err == nil {
			return binary.BigEndian.Uint64(data[:]), nil
		} else {
			return 0, err
		}
	}

	return len, nil
}
