package main

import "os/exec"

func showStatus() error {
	return exec.Command("printf", "%s\\n", "ready").Run()
}

func main() {}
