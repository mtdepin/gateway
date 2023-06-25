package crypto

// mtyw-oss-header  sha1转换而来
const header = "e6edc421c0c7c6bf326ccd5e010fb115c217fe4a"
const Size = 1024 * 1024 * 2

// HeadInfo 文件填充的加密信息
type HeadInfo struct {
	Version string `json:"version"`
	EnSize  int64  `json:"EnSize"`
	Parts   []struct {
		Number     int   `json:"number"`
		Size       int64 `json:"size"`
		ActualSize int64 `json:"actualSize"`
	} `json:"parts"`
}

// AddHeader 文件添加标志头
func AddHeader(info []byte) [Size]byte {
	var content [Size]byte
	h := []byte(header)
	hLen := len(h)
	copy(content[:hLen], h)       // 添加头
	copy(content[hLen:], info[:]) // 添加信息
	copy(content[Size-hLen:], h)  // 添加头
	return content
}

// CheckHeader 检验是否是加密上传
func CheckHeader(b [Size]byte) ([]byte, bool) {
	r := string(b[:40])
	tag := string(b[Size-40:])
	return b[40 : Size-40], r == header && tag == header
}
