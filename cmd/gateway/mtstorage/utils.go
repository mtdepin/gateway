package mtstorage

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	TimeFormat = "2006-01-02T15:04:05Z07:00"
)

func writeJson(w http.ResponseWriter, httpStatus int, obj interface{}) (err error) {
	var bytes []byte
	bytes, err = json.Marshal(obj)
	if err != nil {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_, err = w.Write(bytes)
	return
}

func writeJsonQuiet(w http.ResponseWriter, httpStatus int, obj interface{}) {
	if err := writeJson(w, httpStatus, obj); err != nil {
		fmt.Printf("error writing JSON %s: %v", obj, err)
	}
}
func writeJsonError(w http.ResponseWriter, httpStatus int, err error) {
	m := make(map[string]interface{})
	m["error"] = err.Error()
	writeJsonQuiet(w, httpStatus, m)
}

//0 current method;1 up method ....
func DebugPrint(skip int) {
	//funcName, file, lin, ok := runtime.Caller(skip)
	//if ok {
	//	fmt.Println("execute method:", runtime.FuncForPC(funcName).Name())
	//	fmt.Println("file:", file, "line:", lin)
	//}
}

func checkObject(object string) string {
	oss := strings.Split(object, "//")
	length := len(oss)
	if length > 1 {
		object = oss[length-1]
	} else {
		object = oss[0]
	}
	return object
}
