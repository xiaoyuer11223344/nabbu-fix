package main

import (
	"context"
	"errors"
	"os"
	"os/user"

	"github.com/xiaoyuer11223344/nabbu-fix/v2/internal/testutils"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/privileges"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/result"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/runner"
)

var libraryTestcases = map[string]testutils.TestCase{
	"sdk - one passive execution":          &naabuPassiveSingleLibrary{},
	"sdk - one execution - connect":        &naabuSingleLibrary{scanType: "c"},
	"sdk - multiple executions - connect":  &naabuMultipleExecLibrary{scanType: "c"},
	"sdk - one execution - connect - nmap": &naabuSingleExecNmapLibrary{scanType: "c"},

	"sdk - one execution - syn":       &naabuSingleLibrary{scanType: "s"},
	"sdk - multiple executions - syn": &naabuMultipleExecLibrary{scanType: "s"},
}

type naabuPassiveSingleLibrary struct {
}

func (h *naabuPassiveSingleLibrary) Execute() error {
	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80,8080,443,8899",
		Passive:   true,
		OnResult:  func(hr *result.HostResult) {},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer naabuRunner.Close()

	return naabuRunner.RunEnumeration(context.TODO())
}

type naabuSingleLibrary struct {
	scanType string
}

func (h *naabuSingleLibrary) Execute() error {
	if h.scanType == "s" && !privileges.IsPrivileged {
		usr, _ := user.Current()
		return errors.New("invalid user" + usr.Name)
	}

	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("scanme.sh"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80,8080,443,8899",
		ScanType:  h.scanType,
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}
	defer naabuRunner.Close()

	if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
		return err
	}
	if !got {
		return errors.New("no results found")
	}

	return nil
}

type naabuMultipleExecLibrary struct {
	scanType string
}

func (h *naabuMultipleExecLibrary) Execute() error {
	if h.scanType == "s" && !privileges.IsPrivileged {
		usr, _ := user.Current()
		return errors.New("invalid user" + usr.Name)
	}

	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("sockett.1-tree.com.cn"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80,8080,443,8899",
		ScanType:  h.scanType,
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
	}

	for i := 0; i < 3; i++ {
		naabuRunner, err := runner.NewRunner(&options)
		if err != nil {
			return err
		}

		if err = naabuRunner.RunEnumeration(context.TODO()); err != nil {
			return err
		}
		if !got {
			return errors.New("no results found")
		}
		naabuRunner.Close()
	}
	return nil
}

type naabuSingleExecNmapLibrary struct {
	scanType string
}

func (h *naabuSingleExecNmapLibrary) Execute() error {
	if h.scanType == "s" && !privileges.IsPrivileged {
		usr, _ := user.Current()
		return errors.New("invalid user" + usr.Name)
	}

	testFile := "test.txt"
	err := os.WriteFile(testFile, []byte("www.zj-1-tree.com.cn\nfilet.1-tree.com.cn"), 0644)
	if err != nil {
		return err
	}
	defer os.RemoveAll(testFile)

	var got bool

	options := runner.Options{
		HostsFile: testFile,
		Ports:     "80,8080,443,8899",
		ScanType:  h.scanType,
		Nmap:      true,
		NmapOj:    false,
		NmapOx:    true,
		NmapCLI:   "nmap -Pn -sV -T5 --open -oX /tmp/${uuid} -script-args http.useragent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'",
		OnResult: func(hr *result.HostResult) {
			got = true
		},
		WarmUpTime: 2,
	}

	r, err := runner.NewRunner(&options)
	if err != nil {
		return err
	}

	if err = r.RunEnumeration(context.TODO()); err != nil {
		return err
	}

	if !got {
		return errors.New("no results found")
	}
	r.Close()

	return nil
}
