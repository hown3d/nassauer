package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/cmd/bpf2go/gen"
)

var (
	objFileName string
	target      string
	pkg         string
)

func run(identStem string) error {
	if pkg == "" {
		return errors.New("missing package, you should either set the go-package flag or the GOPACKAGE env")
	}

	var err error
	removeOnError := func(f *os.File) {
		if err != nil {
			os.Remove(f.Name())
		}
		f.Close()
	}
	spec, err := ebpf.LoadCollectionSpec(objFileName)
	if err != nil {
		return fmt.Errorf("can't load BPF from ELF: %s", err)
	}

	var maps []string
	for name := range spec.Maps {
		// Skip .rodata, .data, .bss, etc. sections
		if !strings.HasPrefix(name, ".") {
			maps = append(maps, name)
		}
	}

	var variables []string
	for name := range spec.Variables {
		variables = append(variables, name)
	}

	var programs []string
	for name := range spec.Programs {
		programs = append(programs, name)
	}

	types := gen.CollectGlobalTypes(spec)

	target, goarches, err := gen.FindTarget(target)
	if err != nil {
		return err
	}

	// Write out generated go
	outputStem := strings.ToLower(identStem)
	stem := fmt.Sprintf("%s_%s", outputStem, target.Suffix())

	absOutPath, err := filepath.Abs(".")
	if err != nil {
		return err
	}
	goFileName := filepath.Join(absOutPath, stem+".go")
	goFile, err := os.Create(goFileName)
	if err != nil {
		return err
	}
	defer removeOnError(goFile)

	objectFileBase := filepath.Base(objFileName)
	if err := os.Remove(objectFileBase); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Link(objFileName, objectFileBase); err != nil {
		return err
	}

	slog.Info("generating", "package", pkg)
	err = gen.Generate(gen.GenerateArgs{
		Package:     pkg,
		Stem:        identStem,
		Constraints: goarches.Constraint(),
		Maps:        maps,
		Variables:   variables,
		Programs:    programs,
		Types:       types,
		ObjectFile:  objectFileBase,
		Output:      goFile,
	})
	if err != nil {
		return fmt.Errorf("can't write %s: %s", goFileName, err)
	}

	slog.Debug("Generated bpf2go binding", "file", goFileName)

	// if b2g.makeBase == "" {
	// 	return
	// }

	// deps, err := parseDependencies(cwd, depInput)
	// if err != nil {
	// 	return fmt.Errorf("can't read dependency information: %s", err)
	// }

	// depFileName := goFileName + ".d"
	// depOutput, err := os.Create(depFileName)
	// if err != nil {
	// 	return fmt.Errorf("write make dependencies: %w", err)
	// }
	// defer depOutput.Close()

	// // There is always at least a dependency for the main file.
	// deps[0].file = goFileName
	// if err := adjustDependencies(depOutput, b2g.makeBase, deps); err != nil {
	// 	return fmt.Errorf("can't adjust dependency information: %s", err)
	// }

	// b2g.Debugln("Wrote dependency", "file", depFileName)

	return nil
}

func collectCTypes(types *btf.Spec, names []string) ([]btf.Type, error) {
	var result []btf.Type
	for _, cType := range names {
		typ, err := types.AnyTypeByName(cType)
		if err != nil {
			return nil, err
		}
		result = append(result, typ)
	}
	return result, nil
}

func main() {
	flag.StringVar(&objFileName, "object-file-name", "", "path to ebpf object file")
	flag.StringVar(&target, "target", "bpfel", "architecture")
	flag.StringVar(&pkg, "go-package", "nassauer", "go package")
	flag.Parse()

	if err := run(flag.Arg(0)); err != nil {
		slog.Error("error running rustebpf2go", "error", err)
	}
}
