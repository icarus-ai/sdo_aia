package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ***** ***** ***** ***** *****

type list_t struct { Name, Uri string }

const limit = 2

func main() {
	//var wg sync.WaitGroup
	fn := func(idx int, p, u string) {
		//defer wg.Done()
		//comm_LOGD("%s", p)
		//time.Sleep(1000000)
		if comm_PathExists(p) { return }
		if e := DownloadThread(u, p, nil, 1); e != nil {
			os.Remove(p)
			comm_LOGD("fail: down: %03d %s", idx, p)
			comm_FwriteString(fmt.Sprintf("fail_%03d_%s.log", idx, p), fmt.Sprintf("fail: download thread: %v", e))
		} else { comm_LOGD("download: %03d", idx) }
	}
	d := comm_Fread("fs_list_json")
	if len(d) == 0 {
		comm_LOGD("fail: read: fs_list_json")
		return
	}
	var p []list_t
	if e := json.Unmarshal(d, &p); e != nil {
		comm_LOGD("fail: json: %v", e)
		return
	}
	size := len(p)
	comm_LOGD("size: %d", size)
	for i, v := range p {
		//wg.Add(1)
		fn(i, v.Name, v.Uri)
		//if (i+1)%limit == 0 { wg.Wait() }
	}
	//if size%limit != 0 { wg.Wait() }

	comm_Dir(".", func(path, name string, isdir bool) bool {
		if !isdir {
			for _, v := range p {
				if v.Name == name { return true }
			}
			os.Remove(path+comm_SPF+name)
		}
		return false
	})

	comm_LOGD("download end")
}

// ***** ***** ***** ***** *****

const (
	comm_SPF = string(os.PathSeparator)
	comm_MB  = 1048576
)

var  comm_Mkdir = os.MkdirAll
func comm_LOGD        (f string, a... any) { fmt.Printf(f+"\n", a...) }
func comm_FwriteString(path, v string) { _ = os.WriteFile(path, []byte(v), 0o644) }
func comm_Fread       (path string) []byte {
	if d, e := os.ReadFile(path); e == nil { return d }
	return nil
}
func comm_PathExists(path string) bool {
	if path == "" { return false }
	_, e := os.Stat(path)
	return e == nil || errors.Is(e, os.ErrExist)
}
func comm_Dir(path string, fn func(path, name string, isdir bool) bool) {
	if dir, e := os.ReadDir(path); e == nil {
		for _, v := range dir {
	if v.IsDir() {
		name := v.Name()
		if   fn(path,   name  , true) { comm_Dir(path + comm_SPF + name, fn) }
	} else { fn(path, v.Name(), false) }
} } }

// ***** ***** ***** ***** *****

var binary_pool_buff = sync.Pool { New: func() any { return new(bytes.Buffer) } }

func binary_NewBuff() *bytes.Buffer { return binary_pool_buff.Get().(*bytes.Buffer) }
func binary_PutBuff(v *bytes.Buffer) {
	// See https://golang.org/issue/23199
	if v.Cap() < 32768 { // 大Buffer(32k)直接丢弃
		v.Reset()
		binary_pool_buff.Put(v)
	}
}

type binary_IoWriteBuf interface {
	io.Writer
	io.Seeker
	io.Closer
}

type binary_Writer struct {
	w    io.Writer
	buf *bytes.Buffer
}

func binary_NewWriter(w io.Writer) *binary_Writer { return &binary_Writer { w: w, buf: binary_NewBuff() } }
func (m *binary_Writer) Write(d []byte) (int, error) { return m.buf.Write(d) }
func (m *binary_Writer) Flush() error { _, e := m.buf.WriteTo(m.w); return e }

// ***** ***** ***** ***** *****

func init() {
	http_dia = &net.Dialer {
		Timeout  : 30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	http_transport := &http.Transport {
		Proxy                : http.ProxyFromEnvironment,
		DialContext          : http_dia.DialContext, // newHosts().DialContext,
		ForceAttemptHTTP2    : true,
		DisableCompression   : true,
		MaxIdleConns         : 0, // 所有host的连接池最大连接数量
		MaxIdleConnsPerHost  : 2, // 每个host的连接池最大空闲连接数,默认2
		MaxConnsPerHost      : 0, // 对每个host的最大连接数量，0表示不限制
		IdleConnTimeout      : 90 * time.Second,
		//ResponseHeaderTimeout: 10 * time.Second, // 限制读取response header的时间,默认 timeout + 5*time.Second
		ExpectContinueTimeout:  2 * time.Second,
		TLSHandshakeTimeout  : 10 * time.Second,
		TLSClientConfig      : &tls.Config {
			MinVersion       : tls.VersionTLS12,
			MaxVersion       : tls.VersionTLS13,
			InsecureSkipVerify: true, // 跳过证书验证
			//PreferServerCipherSuites: true,
			//CipherSuites    : k_cipher_suites,
	} }

	http_pool = sync.Pool {
		New: func() any {
			https := &HTTPS{
				cookies : make(MapStr),
				cli     : &http.Client { Transport: http_transport },
				redirect: false,
				location: "",
				def_head: true,
			}
			https.cli.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if https.redirect { return http.ErrUseLastResponse } // 不进入重定向
				return nil
			}
			return https
	} }

	http_cli = NewClient()
}

func NewClient() *HTTPS  { return http_pool.Get().(*HTTPS) }
func PutClient(m *HTTPS) { m.PutClient() }

func (m *HTTPS) PutClient() {
	for k := range m.cookies { delete(m.cookies, k) }
	if transport, ok := m.cli.Transport.(*http.Transport); ok {
		transport.DialContext = http_dia.DialContext
		transport.Proxy       = http.ProxyFromEnvironment
	}
	m.redirect = false
	m.location = ""
	http_pool.Put(m)
}

func (m *HTTPS) http_request(uri, mode string, body io.Reader, heads MapStr) (*http.Request, error) {
	req, e := http.NewRequest(mode, uri, body)
	if   e == nil {
		// 增加header选项
		for k, v := range heads { req.Header.Set(k, v) }
		if m.def_head {
			if _, ok := heads[ACCEPT];       !ok { req.Header.Set(ACCEPT      , "*/*") }
			if _, ok := heads[ACCEPT_LANG];  !ok { req.Header.Set(ACCEPT_LANG , "zh-cn") }
			if _, ok := heads[CONNECTION];   !ok { req.Header.Set(CONNECTION  , "Keep-Alive") }
			if _, ok := heads[USER_AGENT];   !ok { req.Header.Set(USER_AGENT  , USER_AGENT_PC) }
			if _, ok := heads[CONTENT_TYPE]; !ok { req.Header.Set(CONTENT_TYPE, CONTENT_TYPE_HTML) }
	} }
	return req, e
}

// 临时方法 防止重定向过多导致内存泄露
func (m *HTTPS) http_resp_close(v *http.Response) {
	if v != nil && v.Body != nil { _ = v.Body.Close() }
	m.cli.CloseIdleConnections()
}

func http_resp_body(v *http.Response) ([]byte, error) {
	if v      == nil { return nil, http_error_resp }
	if v.Body == nil { return nil, http_error_body }
	data, e := io.ReadAll(v.Body)
	if    e != nil { return nil, e }
	if strings.Contains(v.Header.Get("Content-Encoding"), "gzip") {
		r, e := gzip.NewReader(bytes.NewReader(data))
		if e == nil {
			defer r.Close()
			return io.ReadAll(r)
		}
		return nil, e
	}
	return data, e
}

// ***** ***** ***** *****

func (m *HTTPS) DefaultHeads(v bool) { m.def_head = v }

func (m *HTTPS) GetRedirect() string { return m.location }
func (m *HTTPS) SetRedirect(v bool)  { m.location, m.redirect = "", v }

func (m *HTTPS) GetRspHeader() http.Header { return m.rsp_head }
func (m *HTTPS) GetCookies  () MapStr      { return m.cookies }
func (m *HTTPS) GetCookiesString() string {
	s := ""
	for k, v := range m.cookies { s += ";" + k + "=" + v  }
	if s != "" { return s[1:] }
	return s
}

// ***** ***** ***** *****

func (m *HTTPS) Request(uri, mode string, body io.Reader, heads MapStr) (int, []byte, error) {
	req, e1 := m.http_request(uri, mode, body, heads)
	if   e1 != nil { return -1, nil, e1 }

	rsp, e2 := m.cli.Do(req)

	defer m.http_resp_close(rsp)
	if e2 != nil { return -2, nil, e2 }

	m.rsp_head = rsp.Header

	switch rsp.StatusCode {
		case http.StatusOK:
			if m.cookies != nil {
				for _, cookie := range rsp.Cookies() { m.cookies[cookie.Name] = cookie.Value }
			}
			data, e := http_resp_body(rsp)
			return rsp.StatusCode, data, e
		case http.StatusMovedPermanently, http.StatusFound:
			m.location = rsp.Header.Get("Location")
			data, e := http_resp_body(rsp)
			return rsp.StatusCode, data, e
	}
	data, e := http_resp_body(rsp)
	if    e == nil { return rsp.StatusCode, data, fmt.Errorf("Bad.HTTP.%s.RESP: %s", mode, rsp.Status) }
	return rsp.StatusCode, data, fmt.Errorf("Bad.HTTP.%s.RESP: %s, %v", mode, rsp.Status, e)
}

// ***** ***** ***** *****

func (m *HTTPS) Get(uri string, heads MapStr) []byte {
	if code, d, _ := m.Request(uri, http.MethodGet, nil, heads); code == 200 { return d }
	return nil
}

func (m *HTTPS) Post(uri, body string, heads MapStr) []byte {
	if code, d, _ := m.PostCode(uri, body, heads); code == 200 { return d }
	return nil
}

func (m *HTTPS) GetCode (uri       string, heads MapStr) (int, []byte, error) { return m.Request(uri, http.MethodGet, nil, heads) }
func (m *HTTPS) PostCode(uri, body string, heads MapStr) (int, []byte, error) {
	if body == "" { return m.Request(uri, http.MethodPost, nil, heads) }
	return m.Request(uri, http.MethodPost, strings.NewReader(body), heads)
}

// fkey -> "file", params -> "file": path
func (m *HTTPS) Multipart(uri, fkey, separator string, params, heads MapStr) (int, []byte, error) {
	var f *os.File
	s := params[fkey]
	if s != "" {
		var e error
		if f, e = os.Open(s); e != nil { return 0, nil, e }
		defer func() { _ = f.Close() }()
		if i := strings.LastIndex(s, comm_SPF); i >= 0 { s = s[i+1:] }
		delete(params, fkey)
	}
	body := binary_NewBuff()
	w    := multipart.NewWriter(body)
	defer binary_PutBuff(body)
	if f != nil {
		part, e := w.CreateFormFile(fkey, s)
		if    e != nil {
			_ = w.Close()
			return 0, nil, e
		}
		_, _ = io.Copy(part, f)
	}
	for k, v := range params { _ = w.WriteField(k, v) }
	_ = w.Close()
	if heads     == nil { heads = make(MapStr) }
	if separator == ""  { heads[CONTENT_TYPE] = w.FormDataContentType()
	}  else             {
		// "----WebKitFormBoundary" + random_string(16)
		s = w.FormDataContentType()
		heads[CONTENT_TYPE] = s[:30] + separator
		s = strings.ReplaceAll(body.String(), s[30:], separator)
		body.Reset()
		body.WriteString(s)
	}
	return m.Request(uri, http.MethodPost, body, heads)
}

// ***** ***** ***** *****

func (m *HTTPS) Download(uri string, heads MapStr) []byte {
	if uri != "" {
	for loop:=0; loop<3; loop++ {
		code, data, _ := m.Request(uri, http.MethodGet, nil, heads)
		if code == 200 { return data }
		if code == 404 { return nil }
	} }
	return nil
}

// ***** ***** ***** ***** *****

// 初始化分块或直接下载
func (m *HTTPS) downinit(uri, path string, thread_count int64, heads MapStr) (*block_t, error) {
	req, e := m.http_request(uri, http.MethodGet, nil, heads)
	if   e != nil { return nil, e }
	if thread_count > 1 { req.Header.Set(RANGE, "bytes=0-") }
	//req.Header.Set(ACCEPT_ENCODING, "identity")
	resp, e := m.cli.Do(req)
	defer m.http_resp_close(resp)
	if    e != nil { return nil, e }

	fs, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o666)
	if  e != nil { return nil, e }

	switch resp.StatusCode {
		case http.StatusOK: _, e = fs.ReadFrom(resp.Body); return nil, e
		case 206:
			if resp.ContentLength <= comm_MB { _, e = fs.ReadFrom(resp.Body); return nil, e }
			block       := &block_t { fs: fs, length: resp.ContentLength }
			block.chunk  = block.length / thread_count - 10 // 块大小
			t_offset, i := int64(0), 0
			for t_offset+block.chunk < block.length {
				block.blocks = append(block.blocks, &block_data_t{
					idx  : i,
					begin: t_offset,
					end  : t_offset + block.chunk - 1,
				})
				t_offset += block.chunk; i++
			}
			block.blocks = append(block.blocks, &block_data_t{
				idx  : i,
				begin: t_offset,
				end  : block.length - 1,
			})
			return block, nil
		default: return nil, fmt.Errorf("HTTP 下载失败: %d", resp.StatusCode)
	}
}

// 下载分块
func (m *block_t) downblock(uri string, block *block_data_t, heads MapStr) error {
	cli := NewClient()
	defer cli.PutClient()
	req, e := cli.http_request(uri, http.MethodGet, nil, heads)
	if   e != nil { return e }
	req.Header.Set(RANGE, fmt.Sprintf("bytes=%d-%d", block.begin, block.end))
	//req.Header.Set(ACCEPT_ENCODING, "identity")
	resp, e := cli.cli.Do(req)
	defer cli.http_resp_close(resp)
	if    e != nil { return e }

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= 300 { return fmt.Errorf("HTTP: 下载分块[%d]失败: %d", block.idx, resp.StatusCode) }
	start := block.begin
	//cache := bufio.NewWriter(m.fs)
	cache := binary_NewWriter(m.fs)
	defer func() {
		m.lock.Lock()
		_, _ = m.fs.Seek(start, io.SeekStart)
		_    = cache.Flush()
		m.lock.Unlock()
	}()

	buffer := make([]byte, 1024)// m.chunk)
	i, size, need := 0, int64(0), int64(0)

	//comm.LOGD("offset: %02d, %d, %d - %d", block.idx, m.chunk, block.begin, block.end)
	for {
		if i, e  = resp.Body.Read(buffer); e != nil && e != io.EOF { return e }
		   need  = block.end - block.begin + 1
		if size  = int64(i); size > need { size, e = need, io.EOF }
		if _, x := cache.Write(buffer[:size]); x != nil { return x }
		block.begin += size
		block.count += size
		if e == io.EOF || block.begin > block.end { break }
	}
	return nil
}

// 使用count个线程将给定URL对应的文件下载至给定Path
func (m *HTTPS) DownloadThread(uri, path string, heads MapStr, count int64) error {
	if uri  == "" { return http_error_down_uri }
	if path == "" { return http_error_down_path }

	if        count > 64 { count = 64
	} else if count <  2 { count = 2 }

	block, e := m.downinit(uri, path, count, heads)
	if e == nil && block != nil {
		defer block.fs.Close()
		var wg sync.WaitGroup
		wg.Add(len(block.blocks))
		for i := range block.blocks {
			go func(id int) {
				defer wg.Done()
				if ee := block.downblock(uri, block.blocks[id], heads); ee != nil { e = ee }
			}(i)
		}
		wg.Wait()
	}
	return e
}

// ***** ***** ***** ***** *****

func GetClient() *HTTPS { return http_cli }

func DefaultHeads        (v bool)                           {        http_cli.DefaultHeads(v) }
func HttpSetRedirect     (v bool)                           {        http_cli.SetRedirect (v) }
func HttpGetRedirect     ()                          string { return http_cli.GetRedirect ( ) }
func HttpGetCookies      ()                          MapStr { return http_cli.GetCookies  ( ) }
func HttpGetCookiesString()                          string { return http_cli.GetCookiesString() }

func HttpGet        (uri       string, heads MapStr) []byte { return http_cli.Get (uri,       heads) }
func HttpPost       (uri, body string, heads MapStr) []byte { return http_cli.Post(uri, body, heads) }

func Download       (uri       string, heads MapStr)              []byte { return http_cli.Download(uri, heads) }
func DownloadThread (uri, path string, heads MapStr, count int64) error  { return http_cli.DownloadThread(uri, path, heads, count) }

// ***** ***** ***** ***** ***** *****

const (
	ACCEPT        = "Accept"
	ACCEPT_LANG   = "Accept-Language"
	AUTHORITY     = "authority"
	AUTHORIZATION = "Authorization"
	CONNECTION    = "Connection"
	CONTENT_TYPE  = "Content-Type"
	CONTENT_LEN   = "Content-Length"
	USER_AGENT    = "User-Agent"
	REFERER       = "Referer"
	COOKIE        = "Cookie"
	ORIGIN        = "Origin"

	CONTENT_TYPE_HTML  = "application/x-www-form-urlencoded"
	CONTENT_TYPE_JSON  = "application/json"
	CONTENT_TYPE_TEXE  = "text/html"

	CHARSET_UTF8       = "charset=utf-8"

	USER_AGENT_ANDROID = "Mozilla/5.0 (Linux; U; Android 8.1.0; zh-cn; Build/2.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Mobile Safari/537.36"
	USER_AGENT_PC      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
	USER_AGENT_PC_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.61 Safari/537.36 Edg/94.0.992.31"
	USER_AGENT_PC_MAC  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"

	// GET  = http.MethodGet
	// POST = http.MethodPost
)

type (
	MapStr map[string]string

	HTTPS struct {
		cookies  MapStr
		cli     *http.Client
		redirect bool
		location string
		def_head bool
		rsp_head http.Header
	}
)

var (
	http_dia  *net.Dialer
	http_pool sync.Pool
	http_cli  *HTTPS
)

var (
	http_error_resp      = errors.New("no rsp")
	http_error_body      = errors.New("no body")
	http_error_down_uri  = errors.New("down uri nil")
	http_error_down_path = errors.New("down path nii")
)

// ***** ***** ***** ***** ***** *****

const (
	ACCEPT_ENCODING = "Accept-Encoding"
	RANGE           = "range"
)

type (
	block_data_t struct {
		idx   int
		begin int64 // offset
		end   int64 // offset
		count int64
	}

	block_t struct {
		fs        binary_IoWriteBuf
		lock      sync.Mutex
		chunk     int64 // 块大小
		length    int64 // 总长度
		blocks []*block_data_t
	}
)

// ***** ***** ***** ***** ***** *****

var k_cipher_suites = []uint16 {
	// TLS 1.0 - 1.2 cipher suites.
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	// TLS 1.3 cipher suites.
	tls.TLS_AES_128_GCM_SHA256,
	tls.TLS_AES_256_GCM_SHA384,
	tls.TLS_CHACHA20_POLY1305_SHA256,
	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator that the client is doing version fallback. See RFC 7507.
	tls.TLS_FALLBACK_SCSV,
	// Legacy names for the corresponding cipher suites with the correct _SHA256 suffix, retained for backward compatibility.
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
}
