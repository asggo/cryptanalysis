package cryptanalysis

import (
    "bytes"
    "testing"
)

func TestChunk(t *testing.T) {
    data := []byte("TESTDATA")

    res3 := [][]byte{}
    res3 = append(res3, []byte("TES"))
    res3 = append(res3, []byte("TDA"))
    res3 = append(res3, []byte("TA\x01"))

    res4 := [][]byte{}
    res4 = append(res4, []byte("TEST"))
    res4 = append(res4, []byte("DATA"))
    res4 = append(res4, []byte("\x04\x04\x04\x04"))

    c3 := Chunk(data, 3)
    c4 := Chunk(data, 4)

    for i, _ := range res3 {
        if bytes.Compare(res3[i], c3[i]) != 0 {
            t.Error("Expected", res3, "got", c3)
        }
    }

    for i, _ := range res4 {
        if bytes.Compare(res4[i], c4[i]) != 0 {
            t.Error("Expected", res4, "got", c4)
        }
    }
}


func TestTranspose(t *testing.T) {
    m1 := [][]byte{}
    m1 = append(m1, []byte{1, 2})
    m1 = append(m1, []byte{3, 4})

    m2 := [][]byte{}
    m2 = append(m2, []byte{1, 3})
    m2 = append(m2, []byte{2, 4})

    m3 := Transpose(m1)

    for i, _ := range m2 {
        if bytes.Compare(m2[i], m3[i]) != 0 {
            t.Error("Expected", m2, "got", m3)
        }
    }
}


func TestPadPkcs7(t *testing.T) {
    str := []byte("YELLOW SUBMARINE")
    pad := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
    pkcs := PadPkcs7(str, 20)

    if bytes.Compare(pkcs, pad) != 0 {
        t.Error("Expected", pad, "got", pkcs)
    }
}
