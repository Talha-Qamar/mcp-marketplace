package main

import "os/exec"

func run(cmd string) { exec.Command("sh", "-c", cmd).Run() }

func main() {}
