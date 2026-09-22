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

const (
	authMechTd2Oid    = "1.3.6.1.4.1.191.1.1012.1.1.9"
	authMechJwtOid    = "1.3.6.1.4.1.28698.4.302.1.4"
	authMechLdapOid   = "1.3.6.1.4.1.191.1.1012.1.20"
	authMechTdNegoOid = "1.3.6.1.4.1.28698.4.302.1.3"
	authMechGssOid    = "1.3.6.1.4.1.191.1.1012.1.6"
)

type authMechFlag uint8

const (
	authMechTd2 = 1 << iota
	authMechJwt
	authMechLdap
	authMechTdNego
	authMechGss
)

type authMech struct {
	isDefault          bool
	cidBypassSupported bool
	rank               int
}

func decodeAuthMetch(mech string) authMechFlag {
	switch mech {
	case authMechTd2Oid:
		return authMechTd2
	case authMechJwtOid:
		return authMechJwt
	case authMechLdapOid:
		return authMechLdap
	case authMechTdNegoOid:
		return authMechTdNego
	case authMechGssOid:
		return authMechGss
	}
	return 0
}

type gssContext interface {
	establishSecureChannel(con *teradataConnection) error
	wrap(buff []byte) ([]byte, error)
	unwrap(buff []byte) ([]byte, error)
}
