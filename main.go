package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const TimestampLayout = "2006-01-02T15:04:05.000Z"

//sha256(sharedSecret+hmac(sharedSecret, nonce))
func verifyIdentity(r *http.Request) (error, bool) {
	ss := []byte("dazar123")
	str := r.Header.Get("sno")
	if str == "" {
		return nil, false
	}

	now := time.Now().UTC().Add(8 * time.Hour)
	nonce := []string{now.Format(TimestampLayout[:16]), now.Add(time.Minute).Format(TimestampLayout[:16]), now.Add(-1 * time.Minute).Format(TimestampLayout[:16])}
	for _, n := range nonce {
		mac := hmac.New(sha256.New, ss)
		mac.Write([]byte(n))
		if str == fmt.Sprintf("%x", sha256.Sum256(append(ss, mac.Sum(nil)...))) {
			return nil, true
		}
	}
	return nil, false
}
func getBin(w http.ResponseWriter, r *http.Request) {
	e,b:=verifyIdentity(r)
	if e != nil {
		http.Error(w, e.Error(), 503)
		return
	}
	if b == false {
		http.Error(w, "unauthorized access", 401)
		return
	}
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		fmt.Print("can't read body")
		return
	}
	// "/f10a/bin/2020-01-01.a", "/codename.pkl"
	prefix:="/home/ubuntu/f10_serverside"
	binPath := prefix+string(bodyBytes)

	// provide resource
	fi, err := os.Stat(binPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		fmt.Print("path error")
		return
	}
	// get the size
	size := fi.Size()
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	filepath := strings.Split(binPath, "/")
	w.Header().Set("Content-Disposition", "attachment; filename="+filepath[len(filepath)-1])
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, binPath)
}
func main() {
	http.HandleFunc("/f10bin", getBin)
	http.ListenAndServe("127.0.0.1:7890", nil)
}