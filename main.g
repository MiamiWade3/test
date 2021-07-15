package main

import (
	"fmt"
	"strings"
	"strconv"
	"math"
	"time"
	"math/rand"
	"flag"
	"path/filepath"
	"os"
	"net/http" a 
	"io/ioutil"
	"encoding/json"
	"regexp"
	"net/url"
	"wesure.com/ossutils/utils"
	"encoding/base64"
	"crypto/des"
	"crypto/cipher"
	"bytes"
)

func main(){
	fmt.Printf("%s\n", convertOctonaryUtf8("\345\244\247\347\216\213\345\217\253\346\210\221\346\235\245\345\267\241\345\261\261"))
	st := "2019-11-21 11:59:01"
	fmt.Printf("%s\n", st)
	t, _ := time.ParseInLocation("2006-01-02 15:04:05", st, time.Local)
	fmt.Println(t.Unix())

	tt := time.Unix(t.Unix(), 0)
	fmt.Println(tt.Format("2006-01-02 15:04:05"))
	//testwofresource_image()
	/*
	key := "c51d12ea6b4d21327d301325defb9ee0"
	content := "hello mikemai"
	data, err := Encrypt([]byte(content), key)
	if err != nil {
		fmt.Printf("fail to Encrypt %s\n", err.Error())
		return
	}
	fmt.Printf("data:%s\n", data)
	text, e := Decrypt(data, key)
	if e != nil {
		fmt.Printf("fail to Decrypt %s\n", err.Error())
		return
	}
	fmt.Printf("text:%s\n", text)

	if checkShortUrl("https://w-sit.weurl.net/48s3g") {
		fmt.Printf("good\n")
	} else {
		fmt.Printf("bad\n")
	}*/
	/*
	f, err := os.Open("weak_password.txt")
	if err != nil {
		fmt.Printf("can not open weakpassword file:%s\n", err.Error())
		panic(err)
	}
	defer f.Close()
	rd := bufio.NewReader(f)
	out := ""
	for {
		line, _, err := rd.ReadLine() //ReadString('\n') //以'\n'为结束符读入一行
		if err != nil || io.EOF == err {
			break
		}
		//line = line[:len(line) - 1 ]
		if err = validatePassword(string(line));err == nil {
			//fmt.Printf("line [%s]\n", line)
			out = fmt.Sprintf("%s\n%s", out, line)
		}
	}
	f1,err := os.OpenFile("weak_password_ok.txt", os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0666)
	defer f1.Close()
	if err != nil {
		fmt.Printf("fail to open file %s", err.Error())
		return
	}
	_,err = f1.Write([]byte(out))*/
	//kibana()

	//短链测试代码
	/*
	t := flag.String("short", "", "short string")
	flag.Parse()
	short2int(*t)
	*/

	/*
	t := flag.String("type", "", "encode type encrypt/decrypt")
	key := flag.String("key", "", "encode key")
	text := flag.String("text", "", "code text")

	flag.Parse()

    fmt.Printf("type:%s\n", *t)
	fmt.Printf("key:%s\n", *key)
    fmt.Printf("text:%s\n\n", *text)

	fmt.Printf("%s\n", time.Now().Format("2006-01-02 15:04:05.000"))
	return
	if *t == "encrypt" {
	    plain, err := Encrypt([]byte(*text), []byte(*key), true)
	    if err != nil {
		fmt.Printf("Encrypt err:%s\n", err.Error())
		return
	    }
	    fmt.Printf("encrypt:%s\n", plain)
	} else {
	    cipher, err := Decrypt([]byte(*text), []byte(*key), true)
            if err != nil {
                fmt.Printf("Decrypt err:%s\n", err.Error())
                return
            }
	    fmt.Printf("decrypt:%s\n", cipher)
	}*/
}

/*
func Encrypt(plainText []byte, key []byte, withHexEncode bool) ([]byte, error) {

	keyc, err := hex.DecodeString(string(key))
	if err != nil {
		return nil, err
	}

	encode, err := encrypt(plainText, keyc)
	if err != nil {
		return nil, err
	}

	if withHexEncode {
		encode = []byte(hex.EncodeToString(encode))
	}
	return encode, nil
}

func Decrypt(cipherText []byte, key []byte, withHexDecode bool) ([]byte, error) {
	keyc, err := hex.DecodeString(string(key))
	if err != nil {
		return nil, err
	}
	if withHexDecode {
		cipherText, err = hex.DecodeString(string(cipherText))
		if err != nil {
			return nil, err
		}
	}
	decode, err := decrypt(cipherText, keyc)
	if err != nil {
		return nil, err
	}
	return decode, nil
}

func encrypt(plainText []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	plainText = PKCS5Padding(plainText)
	if len(plainText)%aes.BlockSize != 0 {
		return nil, errors.New("length of plain text is invalid")
	}

	cipherText := make([]byte, 0)
	text := make([]byte, aes.BlockSize)
	for len(plainText) > 0 {
		cipher.Encrypt(text, plainText)
		plainText = plainText[aes.BlockSize:]
		cipherText = append(cipherText, text...)
	}
	return cipherText, nil
}

func decrypt(cipherText []byte, key []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return nil, errors.New("length of cipher text is invalid")
	}

	plainText := make([]byte, 0)
	text := make([]byte, 16)
	for len(cipherText) > 0 {
		cipher.Decrypt(text, cipherText)
		cipherText = cipherText[aes.BlockSize:]
		plainText = append(plainText, text...)
	}

	unpadded := PKCS5UPadding(plainText)
	if unpadded == nil {
		return nil, errors.New("failed to PKCS5UPadding")
	}

	return unpadded, nil
}

func PKCS5Padding(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padded := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padded...)
}

func PKCS5UPadding(data []byte) []byte {
	length := len(data)
	if length < 8 {
		return nil
	}
	unpadding := int(data[length-1])
	if length <= unpadding {
		return nil
	}
	return data[:(length - unpadding)]
}
*/

func testwofresource_image()  {
	b, err := ioutil.ReadFile("./test.jpeg")
	if err != nil {
		fmt.Printf("fail to read file, %s\n", err.Error())
		return
	}
	resp, err := http.Post("http://10.0.32.201:8070/wofresource/image/resize?format=jpeg&quality=10&height=800",
		"image/jpeg", bytes.NewBuffer(b))
	if err != nil {
		fmt.Printf("fail to Post, %s\n", err.Error())
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("response code %d\n", resp.StatusCode )
		return
	}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	err = ioutil.WriteFile("./new.jpeg", bodyBytes, 0644)
	if err != nil {
		fmt.Printf("fail to WriteFile, %s\n", err.Error())
		return
	}
}
// map根据value找key
func findkey(in string) int64 {
	var tenToAny map[int64]string = map[int64]string{
		0: "Z", 1: "1", 2: "l", 3: "Q", 4: "e", 5: "8", 6: "6", 7: "7", 8: "5", 9: "9",
		10: "F", 11: "b", 12: "c", 13: "d", 14: "4", 15: "f", 16: "g", 17: "h", 18: "i", 19: "j",
		20: "k", 21: "2", 22: "G", 23: "H", 24: "o", 25: "p", 26: "r", 27: "q", 28: "s", 29: "D",
		30: "u", 31: "v", 32: "w", 33: "x", 34: "y", 35: "U", 36: "A", 37: "B", 38: "X", 39: "t",
		40: "E", 41: "a", 42: "m", 43: "n", 44: "R", 45: "J", 46: "K", 47: "L", 48: "M", 49: "N",
		50: "O", 51: "P", 52: "3", 53: "I", 54: "S", 55: "T", 56: "z", 57: "V", 58: "W", 59: "C",
		60: "Y", 61: "0"}

	result := int64(-1)
	for k, v := range tenToAny {
		if in == v {
			result = k
		}
	}
	return result
}

// 任意进制转10进制
func AnyToDecimal(num string, n int) int64 {
	var new_num float64
	new_num = 0.0
	nNum := len(strings.Split(num, "")) - 1
	for _, value := range strings.Split(num, "") {
		tmp := float64(findkey(value))
		if tmp != -1 {
			new_num = new_num + tmp*math.Pow(float64(n), float64(nNum))
			nNum = nNum - 1
		} else {
			break
		}
	}
	return int64(new_num)
}


func short2int(short string) {
	shortNum := AnyToDecimal(short,62)
	shortNumStr := strconv.FormatInt(shortNum, 10)
	l :=len(shortNumStr)
	if l <= 6 {
		fmt.Print("shortUrl is invalid")
		return
	}
	dataStr := shortNumStr[0:2] + shortNumStr[l-4:l]
	num, err := strconv.Atoi(shortNumStr[2:l-4])
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Printf("short %s to int %d dataStr %s\n", short, num, dataStr)
	return
}
func atoi(str string) int {
	i, e := strconv.Atoi(str)
	if e != nil {
		return 0
	}
	return i
}

func aaaa(str string) {
	t := strings.Split(str, "/")
	if len(t) == 3 {
		m := atoi(t[1])
		d := atoi(t[2])
		if m == 0 || d == 0{
			fmt.Printf("m %d d %d\n", m, d)
		}else{
			tstr := fmt.Sprintf("%s/%02d/%02d", t[0], m, d)
			tt, err := time.Parse("2006/01/02", tstr)
			if err != nil {
				fmt.Printf("time.Parse %s\n", err.Error())
			}
			fmt.Printf("tt %s\n", tt.String())
		}
	} else {
		fmt.Printf("len(t) %d\n", len(t))
	}
}

func random() {
	rand.Seed(1234)
	r := 0
	for i := 0; i <= 10; i++{
		r = rand.Intn(20)
		fmt.Printf("1 i %d r %d\n", i, r)
	}

	for i := 0; i <= 10; i++{
		r = rand.Intn(20)
		fmt.Printf("2 i %d r %d\n", i, r)
	}
}

//////////////////////////////////////////////////////////////////
var gurl = "https://logging.inwesure.com/gz/elasticsearch/_msearch?rest_total_hits_as_int=true&ignore_throttled=false"
type json_info struct {
	Addr string `json:"remote_addr"`
	Path string `json:"path"`
	Host string `json:"host"`
	Account string `json:"account"`
}

type source_info struct {
	Json json_info `json:"json"`
}

type hits_info struct {
	Source source_info `json:"_source"`
}

type es_hits_info struct {
	Total int `json:"total"`
	Hits []hits_info `json:"hits"`
}
type es_resp_info struct {
	Hits es_hits_info `json:"hits"`
}
type es_info struct {
	Resp []es_resp_info `json:"responses"`
}

func get_path_acc(cookie, server, path string) (resip string){
	now := time.Now()
	reqbody := fmt.Sprintf("{\"index\":\"logstash-solomon-*\",\"ignore_unavailable\":true,\"preference\":1604488382773}\n{\"version\":true,\"size\":2000,\"sort\":[{\"@timestamp\":{\"order\":\"desc\",\"unmapped_type\":\"boolean\"}}],\"_source\":{\"excludes\":[]},\"aggs\":{\"2\":{\"date_histogram\":{\"field\":\"@timestamp\",\"interval\":\"30m\",\"time_zone\":\"Asia/Shanghai\",\"min_doc_count\":1}}},\"stored_fields\":[\"*\"],\"script_fields\":{},\"docvalue_fields\":[{\"field\":\"@timestamp\",\"format\":\"date_time\"},{\"field\":\"inputDate\",\"format\":\"date_time\"},{\"field\":\"timeWall\",\"format\":\"date_time\"},{\"field\":\"timeWallstr\",\"format\":\"date_time\"}],\"query\":{\"bool\":{\"must\":[{\"range\":{\"@timestamp\":{\"gte\":%d,\"lte\":%d,\"format\":\"epoch_millis\"}}}],\"filter\":[{\"bool\":{\"filter\":[{\"bool\":{\"should\":[{\"query_string\":{\"fields\":[\"json.path\"],\"query\":\"*%s*\"}}],\"minimum_should_match\":1}},{\"bool\":{\"should\":[{\"query_string\":{\"fields\":[\"json.host\"],\"query\":\"%s*\"}}],\"minimum_should_match\":1}}]}}],\"should\":[],\"must_not\":[{\"match_phrase\":{\"json.account\":{\"query\":\"\"}}}]}},\"highlight\":{\"pre_tags\":[\"@kibana-highlighted-field@\"],\"post_tags\":[\"@/kibana-highlighted-field@\"],\"fields\":{\"*\":{}},\"fragment_size\":2147483647},\"timeout\":\"50000ms\"}\n",
		(now.Unix() - (7*24*3600)) * 1000 , now.Unix() * 1000, path, server)
	fmt.Printf("reqbody %s\n", reqbody)
	client := &http.Client{}
	req, err := http.NewRequest("POST", gurl, strings.NewReader(reqbody))
	if err != nil {
		fmt.Printf("fail to NewRequest %s\n", err.Error())
		return
	}

	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Cookie", cookie)
	req.Header.Set("kbn-version", "6.8.4")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("fail to request %s\n", err.Error())
		return
	}
	if resp.StatusCode != 200 {
		fmt.Printf("response code %d\n", resp.StatusCode)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("fail to ReadAll %s\n", err.Error())
		return
	}

	var resp_info es_info
	err = json.Unmarshal(body, &resp_info)
	if err != nil {
		fmt.Printf("fail to Unmarshal %s\n", err.Error())
		return
	}
	if len(resp_info.Resp) != 1 {
		fmt.Printf("resp_info len %d\n", len(resp_info.Resp))
		return
	}
	fmt.Printf("resp_info hits total %d\n", resp_info.Resp[0].Hits.Total)
	pathmap := make(map[string]map[string]bool)
	for _, h := range resp_info.Resp[0].Hits.Hits {
		acc, ok := pathmap[h.Source.Json.Path]
		if !ok {
			acc = make(map[string]bool)
			acc[h.Source.Json.Account] = false
		} else {
			acc[h.Source.Json.Account] = false
		}
		pathmap[h.Source.Json.Path] = acc
	}

	output := ""
	for k, p := range pathmap {
		output += k + "\t"
		for k, _ := range p {
			output += "," + k
		}
		output += "\n"
	}
	return output
}
func kibana() {
	cookie := flag.String("cookie", "", "cookie")
	host := flag.String("host", "", "host")
	path := flag.String("path", "", "path")
	flag.Parse()
	if *cookie == "" {
		*cookie = "gosessionid=bWlrZW1haS1lNjk5Y2YwYjFlN2IxMWViYTRiOTUyNTQwMDZhYjlkNy1zb2xvbW9u"
	}
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))  //返回绝对路径  filepath.Dir(os.Args[0])去除最后一个元素的路径
	if err != nil {
		fmt.Println(err)
		return
	}
	outputf := dir+"/output.txt"
	f ,err := os.OpenFile(outputf, os.O_WRONLY | os.O_CREATE | os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("fail to open file %s, %s\n", outputf, err.Error())
		return
	}
	defer f.Close()
	_,err = f.Write([]byte(get_path_acc(*cookie,*host,*path)))
	if err != nil {
		fmt.Printf("fail to write %s %s\n", outputf, err.Error())
		return
	}

	fmt.Printf("result output to %s\n", outputf)
}

func validatePassword(pwd string) error {
	if len(pwd) < 8 {
		return fmt.Errorf("密码长度不能少于8位")
	}
	//密码组合校验
	mess := make([]string,0)
	matCount := 0
	reg := regexp.MustCompile(`[a-z]`)
	mat := reg.MatchString(pwd)
	if mat {
		matCount += 1
	} else {
		mess = append(mess, "小写字母")
	}

	reg = regexp.MustCompile(`[A-Z]`)
	mat = reg.MatchString(pwd)
	if mat {
		matCount += 1
	} else {
		mess = append(mess, "大写字母")
	}

	reg = regexp.MustCompile(`[0-9]`)
	mat = reg.MatchString(pwd)
	if mat {
		matCount += 1
	} else {
		mess = append(mess, "数字")
	}

	//reg = regexp.MustCompile(`[~!@#$%^&*()+=|{}:;",.<>\\/?~！@#￥%……&*（）—+|{}\[\]【】‘；：”“’。，、？]`)
	reg = regexp.MustCompile(`[~!@#$%^&*()_+\-=\\|\[\]{};:'",./<>? ！￥……（）—【】‘’；：“”。，、？]`)
	mat = reg.MatchString(pwd)
	if mat {
		matCount += 1
	} else {
		mess = append(mess, "特殊字符")
	}
	if matCount < 3 {
		return fmt.Errorf("必须包含大写/小写字母/数字/特殊字符其中三种；当前只有 %d 种，缺少: %s", matCount, strings.Join(mess, " / "))
	}

	return nil
}

func  checkShortUrl(str string) bool {
	enter, err := url.Parse(str)
	if err != nil {
		fmt.Printf("url.Parse %s\n", err.Error())
		return false
	}
	if enter.Path == "/" {
		fmt.Printf("path is /\n")
		return false
	}
	tmp := strings.Split(enter.Path, "/")
	if len(tmp) != 2{
		fmt.Printf("len(tmp) is %d\n", len(tmp))
		return false
	}

	pathLast := tmp[1]
	dateStr, id, err := utils.ParseShortUrl(pathLast)
	if err != nil {
		fmt.Printf("ParseShortUrl err %sn", err.Error())
		return false
	}
	fmt.Printf("day:%s id:%d\n", dateStr, id)
	//判断id
	if id < 0 {
		fmt.Printf("ParseShortUrl id %d\n", id)
		return false
	}
	//判断时间格式 YYMMDD
	t, err := time.Parse("060102", dateStr)
	if err != nil {
		fmt.Printf("time.Parse err %s\n", err)
		return false
	}
	//日期比今天还大，无效
	if t.Unix() > time.Now().Unix() {
		fmt.Printf("over today, now:%d tomollow %d %d\n",time.Now().Unix(), t.AddDate(0,0, 1).Unix(), t.Unix())
		return false
	}
	return true
}

func Encrypt(orig []byte, secret string) ([]byte, error) {
	var key []byte
	if len(secret) > 8 {
		key = []byte(secret[:8])
	} else {
		key = []byte(secret)
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data := PKCS5Padding(orig, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(data))
	blockMode.CryptBlocks(crypted, data)
	return []byte(base64.StdEncoding.EncodeToString(crypted)), nil
}

func  Decrypt(crypted []byte, secret string) ([]byte, error) {
	baseData, err := base64.StdEncoding.DecodeString(string(crypted))
	if err != nil {
		return nil, err
	}
	var key []byte
	if len(secret) > 8 {
		key = []byte(secret[:8])
	} else {
		key = []byte(secret)
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	data := make([]byte, len(baseData))
	blockMode.CryptBlocks(data, baseData)
	data = PKCS5UnPadding(data)
	return data, nil
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(orig []byte) []byte {
	length := len(orig)
	unpadding := int(orig[length-1])
	return orig[:(length - unpadding)]
}

func convertOctonaryUtf8(in string) string {
	s := []byte(in)
	reg := regexp.MustCompile(`\\[0-7]{3}`)

	out := reg.ReplaceAllFunc(s,
		func(b []byte) []byte {
			i, _ := strconv.ParseInt(string(b[1:]), 8, 0)
			return []byte{byte(i)}
		})
	return string(out)
}
