package cryptanalysis

import (
    "errors"
    "math"
    "crypto/rand"
)

func RandomBytes(size int) ([]byte, error) {
    array := make([]byte, size)
    _, err := rand.Read(array)

    if err != nil {
        return array, err
    }

	return array, nil
}


func BytesToInt(b []byte) (uint64, error) {
    var integer uint64
	var size uint
	var i uint

	integer = 0
    size = uint(len(b) - 1)

    if len(b) == 0 || len(b) > 8 {
        return integer, errors.New("Need 1 to 8 bytes to create integer.")
    }

    for i = 0; i < size; i++ {
        integer = integer + (uint64(b[i]) << ((size - i) * 8))
    }

    return integer, nil
}


func RandomIntRange(start, end uint64) (uint64, error) {
    var val uint64
	val = 0

    if start >= end {
        return val, errors.New("Start value must be less than end value.")
    }

    for {
		b, err := RandomBytes(8)
		if err != nil {
			return val, errors.New("Could not read random bytes from OS.")
		}

        val, err = BytesToInt(b)
		if err != nil {
			return val, errors.New("Could not convert bytes to unsigned integer.")
		}

        if (val <= (math.MaxUint64 - (math.MaxUint64 % end))){ break }
    }

    val = val % (end - start)
    val = val + start

    return val, nil
}
