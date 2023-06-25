package crypto

import (
	"fmt"
	"testing"
)

func Test_aESCBCDecrypter(t *testing.T) {
	s := PasswordEncrypt("")
	fmt.Println(s)
	e := PasswordDecrypt("IuVUead5pqYTSud5yKyBP9Ji04yhiOb9Fvkjmx3S6/SiYOVaZrYkwY9MQBObAnRv")
	fmt.Println(e)
}
func TestPasswdToKey(t *testing.T) {
	//passwd := "HKy0Oe5bnSRSh6XcsAurIw=="
	passwd := "d83c025c1f1e10e56d5600583ecb88ee373d7533"
	_, s := PasswdToKey(passwd)
	t.Log(s)
}

func TestBase64Decrypt(t *testing.T) {
	decrypt, _ := Base64Decrypt("NuE7q6aLS4m_ad3FujywX-U9KI76B4jw5Q9fdS8gBvQ=", "NGA2WtbjyWgfER8od5zZghewn4-Mbk2wdLZJoJRz9sN-eZrdS_ySw9qTs82vaV6f")
	b := []byte("\u0002")
	t.Log(string(b), decrypt)
}
