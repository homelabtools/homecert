package main

import (
	"fmt"

	"github.com/homelabtools/homecert/meta"
)

func main() {
	fmt.Println(meta.ModuleName)
	fmt.Println(meta.ProgramFilename)
	fmt.Println(meta.ProgramDir)
	fmt.Println(meta.Version)
}
