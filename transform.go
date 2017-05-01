package cryptanalysis

import ()


func Chunk(data []byte, size int) [][]byte {
    var chunks [][]byte

    for i:=0; i<len(data); i=i+size {
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


func PadPkcs7(data []byte, size int) []byte {
    if len(data) < size {
        pad := size - len(data)
        for i:=0; i<pad; i++ {
            data = append(data, byte(pad))
        }
    }

    return data
}
