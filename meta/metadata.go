// Package meta contains metadata about the program itself
package meta

import (
	"fmt"
	"os"
	"path/filepath"
)

var (
	ProgramDir      string  // Directory that contains the running program
	ProgramFilename string  // Base filename of the running program
	ModuleName      string  // Name of the Go module of this project, passed in by ldflags during build.
	Version         = "TBD" // Program version, populated by ldflags during build
)

func init() {
	if path, err := os.Executable(); err == nil {
		ProgramDir = filepath.Dir(path)
		ProgramFilename = filepath.Base(path)
	} else {
		panic(fmt.Errorf("CRITICAL: failed to determine filename and workding directory of the program, this should not happen and is a bug: %w", err))
	}
}
