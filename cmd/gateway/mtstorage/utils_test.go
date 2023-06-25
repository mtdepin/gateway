package mtstorage

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

var letters = []byte("0123456789abcdefghijklmnopqrstuvwxyz")

func randStrings(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	arc := uint8(0)
	if _, err := rand.Read(b[:]); err != nil {
		return nil
	}
	for i, x := range b {
		arc = x & 35
		b[i] = letters[arc]
	}
	return b
}
func createTempFile(n int, path string) error {
	data := randStrings(n)
	return ioutil.WriteFile(path, data, 0666)
}

func TestSplitFiles(t *testing.T) {
	p := "/home/zhengke/test/a.txt"
	if err := createTempFile(10000, p); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	//splitFile(file,10)
	fmt.Println("Finished")
}
