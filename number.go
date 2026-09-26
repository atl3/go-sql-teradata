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
	"database/sql/driver"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

const (
	numberMaxDigits       = 40
	numberMaxByteLength   = 19
	numberSipScaleAndPrec = -128
)

var numberBigTen = big.NewInt(10)

func numberFromValue(val driver.Value) (*big.Int, int, error) {
	switch v := val.(type) {
	case int64:
		return big.NewInt(v), 0, nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, 0, fmt.Errorf("NUMBER param cannot be %v", v)
		}
		return parseNumberString(strconv.FormatFloat(v, 'e', -1, 64))
	case string:
		return parseNumberString(v)
	case []byte:
		return parseNumberString(string(v))
	}
	return nil, 0, fmt.Errorf("param expecting number data type but provided value is %T", val)
}

func parseNumberString(s string) (*big.Int, int, error) {
	orig := s
	s = strings.TrimSpace(s)
	exp := 0
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		e, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return nil, 0, fmt.Errorf("invalid number value: %q", orig)
		}
		exp = e
		s = s[:i]
	}
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	intPart, fracPart, _ := strings.Cut(s, ".")
	digits := intPart + fracPart
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return nil, 0, fmt.Errorf("invalid number value: %q", orig)
	}
	unscaled, _ := new(big.Int).SetString(digits, 10)
	if neg {
		unscaled.Neg(unscaled)
	}
	return unscaled, len(fracPart) - exp, nil
}

func encodeNumber(unscaled *big.Int, scale int) ([]byte, error) {
	if unscaled.Sign() == 0 {
		return []byte{0}, nil
	}

	u := new(big.Int).Set(unscaled)
	if nDigits := len(new(big.Int).Abs(u).String()); nDigits > numberMaxDigits {
		drop := nDigits - numberMaxDigits
		div := new(big.Int).Exp(numberBigTen, big.NewInt(int64(drop)), nil)
		if nDigits-numberMaxDigits-scale > 0 {
			// truncate
			u.Quo(u, div)
		} else {
			// scale
			u = quoRoundHalfUp(u, div)
		}
		scale -= drop
	}

	// Strip trailing zeros
	digits := u.String()
	trimmed := strings.TrimRight(digits, "0")
	if len(trimmed) < len(digits) {
		scale -= len(digits) - len(trimmed)
		u.SetString(trimmed, 10)
	}

	if scale < math.MinInt16 || scale > math.MaxInt16 {
		return nil, fmt.Errorf("NUMBER scale %d out of range", scale)
	}
	tc := bigIntToTwosComplement(u)
	out := make([]byte, 0, 3+len(tc))
	out = append(out, byte(len(tc)+2))
	out = append(out, byte(uint16(int16(scale))>>8), byte(int16(scale)))
	return append(out, tc...), nil
}

func quoRoundHalfUp(x, y *big.Int) *big.Int {
	q, r := new(big.Int).QuoRem(x, y, new(big.Int))
	if new(big.Int).Lsh(new(big.Int).Abs(r), 1).Cmp(y) >= 0 {
		if x.Sign() < 0 {
			q.Sub(q, big.NewInt(1))
		} else {
			q.Add(q, big.NewInt(1))
		}
	}
	return q
}

func bigIntToTwosComplement(val *big.Int) []byte {
	bitLen := val.BitLen()
	if val.Sign() < 0 {
		bitLen = new(big.Int).Not(val).BitLen() // -v-1
	}
	n := bitLen/8 + 1
	if val.Sign() >= 0 {
		return val.FillBytes(make([]byte, n))
	}
	mod := new(big.Int).Lsh(big.NewInt(1), uint(n*8))
	return new(big.Int).Add(val, mod).FillBytes(make([]byte, n))
}
