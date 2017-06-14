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


func BytesToInt(array []byte) (uint64, error) {
	if len(array) == 0 || len(array) > 8 {
        return uint64(0), errors.New("Need 1 to 8 bytes to create integer.")
    }

    var integer uint64
    size := len(array)

    for i, b := range array {
		shift := uint64((size - i - 1) * 8)
		integer |= uint64(b) << shift
	}

    return integer, nil
}


// Return a random integer in the range [start, end)
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
