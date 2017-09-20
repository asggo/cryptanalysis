package cryptanalysis

import ()

func Chunk(data []byte, size int) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i = i + size {
		chunks = append(chunks, data[i:i+size])
	}

	return chunks
}

func Transpose(data [][]byte) [][]byte {
	var transpose [][]byte

	for i, _ := range data[0] {
		var temp []byte

		for j, _ := range data {
			temp = append(temp, data[j][i])
		}

		transpose = append(transpose, temp)
	}

	return transpose
}

func PadPkcs7(data []byte, block_size int) []byte {
	if block_size > 256 {
		panic("Block size must be less than or equal to 256.")
	}

	mod := len(data) % block_size
	pad := 0

	if mod == 0 {
		pad = block_size
	} else {
		pad = block_size - mod
	}

	for i := 0; i < pad; i++ {
		data = append(data, byte(pad))
	}

	return data
}

func CaesarShift(data string, shift int) string {
	var plain []byte

	for _, c := range data {
		i := int(c)

		switch {
		case i >= 97:
			i = (((i - 97) + shift) % 26) + 97
		default:
			i = (((i - 65) + shift) % 26) + 65
		}

		plain = append(plain, byte(i))
	}

	return string(plain)
}
