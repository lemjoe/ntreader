package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

// Arrays for GUIDs/paths lists
var guids = []string{}
var paths = []string{}

// Structure that describes every found UserAssist entry and sometimes something else
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

// Function converts FILETIME to nanoseconds. Almost the same as in 'syscall' package
func getNano(low, high uint32) int64 {
	// 100-nanosecond intervals since January 1, 1601
	nsec := int64(high)<<32 + int64(low)
	// change starting time to the Epoch (00:00:00 UTC, January 1, 1970)
	nsec -= 116444736000000000
	// convert into nanoseconds
	nsec *= 100
	return nsec
}

// Rot13
func rot13(x byte) byte {
	y := rune(x)
	if y >= 'a' && y <= 'm' || y >= 'A' && y <= 'M' {
		x += 13
	}
	if y >= 'n' && y <= 'z' || y >= 'N' && y <= 'Z' {
		x -= 13
	}
	return x
}

// Progress bar drawing function
func pbDraw(percent int, startTime time.Time) string {
	progressBar := fmt.Sprintf("\r[%v%v%s%s] Processing time: %v seconds", strings.Repeat("#", percent/5), percent, "%", strings.Repeat("_", 20-percent/5), int(time.Now().Sub(startTime).Seconds()))
	return progressBar
}

// Main entry point
func main() {
	// Memorizing current time for debugging purposes
	startTime := time.Now()

	// Parsing command-line arguments
	logFile := flag.String("log", "", "Path to log-file (Example: -log=ntr.log)")
	inputFile := flag.String("in", "NTUSER.DAT", "Path to NTUSER.DAT file (Example: -in=NTUSER/NTUSER7.DAT)")
	outputFile := flag.String("out", "report.txt", "Path to file with output results (Example: -in=out.txt)")
	flag.Parse()

	// Trying to create or open existing log file
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

	// guids file block:
	// Trying to open guids file
	gfile, err := os.Open("guids")
	if err != nil {
		log.Printf("guids file reading error:  %v\r\n", err)
	}
	log.Printf("guids file is correct\r\n")
	defer gfile.Close()
	scanner := bufio.NewScanner(gfile)
	// Reading GUIDs list from file
	t1 := false
	for scanner.Scan() {
		if t1 == false {
			guids = strings.Split(fmt.Sprintln(scanner.Text()), "??")
			t1 = true
		}
		// Reading paths list from file
		paths = strings.Split(fmt.Sprintln(scanner.Text()), "??")
	}
	// Read error check
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	// Trying to create output file
	of, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Output file creating error: %v\r\n", err)
	}
	log.Printf("Output file successfully created\r\n")

	// Some variables
	var substr []byte
	var records []record

	// Begin to process NTUSER.DAT
	log.Printf("Start processing\r\n")
	// Read every 4 bytes of file and compare with signatures
	for i := 0; i < (len(data) / 4); i++ {
		percent := i / (len(data) / 400)
		fmt.Printf("\r%s", pbDraw(percent, startTime))

		//fmt.Printf("offset: %x value: %v utf-8: [ %v ]\n", i*4, data[i*4:(i+1)*4], string(data[i*4:(i+1)*4]))
		// Program met 0x03 0x00 0x00 0x00 0x01 0x00 0x00 0x00 signature. Trying to recognize path to file
		if bytes.Equal(data[i*4:(i+2)*4], []byte{3, 0, 0, 0, 1, 0, 0, 0}) {
			for j, k := i+2, 0; ; j++ {
				//fmt.Printf("offset: %x value: %v utf-8: [ %v ]\n", j*4, data[j*4:(j+1)*4], string(data[j*4:(j+1)*4]))
				if k > 100 {
					substr = nil
					i = j
					break // Path is too long. Going back and looking for the correct entry
				}
				// Program met 0xb0 0xff 0xff 0xff signature. Fill the fields of record in 'records' structure
				if bytes.Equal(data[j*4:(j+1)*4], []byte{176, 255, 255, 255}) {
					tmpTime := getNano(binary.LittleEndian.Uint32(data[(j+16)*4:(j+17)*4]), binary.LittleEndian.Uint32(data[(j+17)*4:(j+18)*4]))
					tmpRecord := record{(i + 2) * 4, pathSwap(string(substr)), binary.LittleEndian.Uint32(data[(j+2)*4 : (j+3)*4]), time.Unix(0, tmpTime)}
					records = append(records, tmpRecord)
					i = j
					substr = nil
					break // Going back and looking for the next entry
				}
				substr = append(substr, rot13(data[j*4]), rot13(data[j*4+1]), rot13(data[j*4+2]), rot13(data[j*4+3]))
				k++

			}

		}
	}

	// Preprocessing of 'records' structure
	lastExec := ""
	fmt.Print("\n")
	for a, b := range records {
		// Checking is last execution time correct
		if b.last.Sub(time.Now()).Hours() > 72 || b.last.Sub(time.Unix(0, 0)).Hours() < 0 {
			lastExec = "No correct data"
		} else {
			lastExec = fmt.Sprintf("%v", b.last)
		}
		// Building output string
		message := []byte(fmt.Sprintf("Number: %v | Offset: %x | File: %v | Runs count: %v | Last launch: %v\r\n", a+1, b.offset, b.path, b.counter, lastExec))
		// Write output string to file
		if *outputFile != "" {
			of.Write(message)
		}
		// Print output string
		fmt.Printf(string(message))
	}
	of.Close()

	// Some final log messages
	log.Printf("End of file\r\n")
	log.Printf("Processing done! Total time: %v\r\n", time.Now().Sub(startTime))
	if *logFile != "" {
		fmt.Printf("Processing done! Total time: %v\r\n", time.Now().Sub(startTime))
	}
}
