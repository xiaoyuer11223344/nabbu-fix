package result

import (
	"fmt"
	"io"
	"log"
	"os"
	"testing"
)

func Test_nmap_xml_parse(t *testing.T) {
	file, err := os.Open("/tmp/8a543897-01e0-4a00-981f-259f66a344f1")
	if err != nil {
		log.Fatalf("file open error: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		log.Fatalf("read file error: %v", err)
	}

	parse, err := NmapResultParse(data)
	if err != nil {
		return
	}

	// 	Scanner          string         `xml:"scanner,attr" json:"scanner"`
	//	Args             string         `xml:"args,attr" json:"args"`
	//	Start            Timestamp      `xml:"start,attr" json:"start"`
	//	StartStr         string         `xml:"startstr,attr" json:"startstr"`
	//	Version          string         `xml:"version,attr" json:"version"`
	//	ProfileName      string         `xml:"profile_name,attr" json:"profile_name"`
	//	XMLOutputVersion string         `xml:"xmloutputversion,attr" json:"xmloutputversion"`
	//	ScanInfo         ScanInfo       `xml:"scaninfo" json:"scaninfo"`
	//	Verbose          Verbose        `xml:"verbose" json:"verbose"`
	//	Debugging        Debugging      `xml:"debugging" json:"debugging"`
	//	TaskBegin        []Task         `xml:"taskbegin" json:"taskbegin"`
	//	TaskProgress     []TaskProgress `xml:"taskprogress" json:"taskprogress"`
	//	TaskEnd          []Task         `xml:"taskend" json:"taskend"`
	//	PreScripts       []Script       `xml:"prescript>script" json:"prescripts"`
	//	PostScripts      []Script       `xml:"postscript>script" json:"postscripts"`
	//	Hosts            []Host         `xml:"host" json:"hosts"`
	//	Targets          []Target       `xml:"target" json:"targets"`
	//	RunStats         RunStats       `xml:"runstats" json:"runstats"`

	//fmt.Println("Scanner: ", parse.Scanner)
	//fmt.Println("Args: ", parse.Args)
	//fmt.Println("Start: ", parse.Start)
	//fmt.Println("StartStr: ", parse.StartStr)
	//fmt.Println("Version: ", parse.Version)
	//fmt.Println("ProfileName: ", parse.ProfileName)
	//fmt.Println("XMLOutputVersion: ", parse.XMLOutputVersion)
	//fmt.Println("ScanInfo: ", parse.ScanInfo)
	//fmt.Println("Verbose: ", parse.Verbose)
	//fmt.Println("Debugging: ", parse.Debugging)
	//fmt.Println("TaskBegin: ", parse.TaskBegin)
	//fmt.Println("TaskProgress: ", parse.TaskProgress)
	//fmt.Println("TaskEnd: ", parse.TaskEnd)
	//fmt.Println("PreScripts: ", parse.PreScripts)
	//fmt.Println("PostScripts: ", parse.PostScripts)

	for _, host := range parse.Hosts {
		for _, addr := range host.Addresses {
			for _, port := range host.Ports {
				fmt.Println(addr.Addr, addr.AddrType, port.Protocol, port.PortId, port.State.State, port.Service.Name, port.Service.Product, port.Service.CPEs)
			}
		}
	}
}
