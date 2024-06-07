// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

package subprocess

import (
	"encoding/binary"
	// "fmt"
	"unsafe"
)

// getEndian returns the desired byte order based on the isLittle parameter
// and the system's endianness.
func getEndian(isLittle bool) binary.ByteOrder {
	var i int32 = 0x01020304
	u := (*[4]byte)(unsafe.Pointer(&i))
	isSystemLittleEndian := u[0] == 0x04
	if isLittle {
		if isSystemLittleEndian {
			// fmt.Printf("system little, returning little when asking for little\n")
			return binary.LittleEndian
		}
		// fmt.Printf("system big, return big when asking for little\n")
		return binary.BigEndian
	} else {
		if isSystemLittleEndian {
			// fmt.Printf("system little, returning big when asking for big\n")
			return binary.BigEndian
		}
		// fmt.Printf("system big, return little when asking for big\n")
		return binary.LittleEndian
	}
}
