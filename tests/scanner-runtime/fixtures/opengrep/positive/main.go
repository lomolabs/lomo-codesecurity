package main

import "os/exec"

func runUserCommand(command string) error {
	return exec.Command("sh", "-c", command).Run()
}

func main() {}
