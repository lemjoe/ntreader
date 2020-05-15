package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

// Flags

var o301, b0ff = false, false

// Guids/paths list
var guids = []string{"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "{6D809377-6AF0-444B-8957-A3773F02200E}", "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}", "{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}", "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}", "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}", "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "E7CF176E110C211B", "308046B0AF4A39CB", "Lister{CECFE544-EF6E-499d-8F87-56B61FA2EC44}"}
var paths = []string{"C:\\Windows\\System32", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\Windows", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs", "Application Data\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned", "Application Data\\Microsoft\\Windows\\Start Menu\\Programs", "C:\\Windows\\SysWOW64", "Mozilla Firefox", "Mozilla Firefox", "Total Commander"}

type record struct {
	offset  int
	path    string
	counter uint32
	last    time.Time
}

// Functioin changes guid to path if it presents in guids array
func pathSwap(init string) string {
	for i, str := range guids {
		charNum := strings.Index(init, str)
		if charNum >= 0 {
			res := []string{paths[i], init[(charNum + len(str)):]}
			return strings.Join(res, "")
		}
	}
	return init
}

// Rot13 implementatioin
func rot13(sb byte) byte {
	s := rune(sb)
	if s >= 'a' && s <= 'm' || s >= 'A' && s <= 'M' {
		sb += 13
	}
	if s >= 'n' && s <= 'z' || s >= 'N' && s <= 'Z' {
		sb -= 13
	}
	return sb
}

// Main entry point
func main() {
	startTime := time.Now()

	// Parsing command-line arguments
	logFile := flag.String("log", "", "Path to log-file")
	inputFile := flag.String("in", "NTUSER.DAT", "Path to NTUSER.DAT file")
	outputFile := flag.String("out", "report.txt", "Path to file with output results")
	flag.Parse()

	// Trying to create log file
	if *logFile != "" {
		lf, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("Log file creating error: %v\r\n", err)
		}
		defer lf.Close()
		log.SetOutput(lf)
		log.Printf("Log file successfully created\r\n")
	}

	// Trying to open NTUSER.DAT file
	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("File reading error:  %v\r\n", err)
	}
	log.Printf("NTUSER.DAT is correct\r\n")

	// Trying to create output file
	of, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Output file creating error: %v\r\n", err)
	}
	log.Printf("Output file successfully created\r\n")

	var substr []byte
	var records []record
	log.Printf("Start processing\r\n")
	for i := 0; i < (len(data) / 4); i++ {
		fmt.Printf("offset: %x value: %v utf-8: [ %v ]\n", i*4, data[i*4:(i+1)*4], string(data[i*4:(i+1)*4]))
		if bytes.Equal(data[i*4:(i+2)*4], []byte{3, 0, 0, 0, 1, 0, 0, 0}) {
			o301 = true
			for j, k := i+2, 0; ; j++ {
				fmt.Printf("offset: %x value: %v utf-8: [ %v ]\n", j*4, data[j*4:(j+1)*4], string(data[j*4:(j+1)*4]))
				if k > 100 {
					substr = nil
					i = j
					break
				}
				if bytes.Equal(data[j*4:(j+1)*4], []byte{176, 255, 255, 255}) {
					b0ff = true
					o301 = false
					tmpTime := syscall.Filetime{binary.LittleEndian.Uint32(data[(j+16)*4 : (j+17)*4]), binary.LittleEndian.Uint32(data[(j+17)*4 : (j+18)*4])}
					tmpRecord := record{(i + 2) * 4, pathSwap(string(substr)), binary.LittleEndian.Uint32(data[(j+2)*4 : (j+3)*4]), time.Unix(0, tmpTime.Nanoseconds())}
					records = append(records, tmpRecord)
					i = j
					substr = nil
					break
				}
				substr = append(substr, rot13(data[j*4]), rot13(data[j*4+1]), rot13(data[j*4+2]), rot13(data[j*4+3]))
				k++

			}

		}
	}
	lastExec := ""
	for a, b := range records {
		if b.last.Sub(time.Now()).Hours() > 72 || b.last.Sub(time.Unix(0, 0)).Hours() < 0 {
			lastExec = "No correct data"
		} else {
			lastExec = fmt.Sprintf("%v", b.last)
		}
		message := []byte(fmt.Sprintf("Number: %v | Offset: %x | File: %v | Runs count: %v | Last launch: %v\r\n", a, b.offset, b.path, b.counter, lastExec))
		if *outputFile != "" {
			of.Write(message)
		}
		fmt.Printf(string(message))
	}
	of.Close()
	log.Printf("End of file\r\n")
	log.Printf("Processing time: %v\r\n", time.Now().Sub(startTime))
}
