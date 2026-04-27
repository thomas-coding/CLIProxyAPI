package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/maintpool"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: %s <status|scan|import|takeout> [flags]", os.Args[0])
	}
	switch os.Args[1] {
	case "status":
		runStatus(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "import":
		runImport(os.Args[2:])
	case "takeout":
		runTakeout(os.Args[2:])
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	_ = fs.Parse(args)

	app, env := mustLoadApp(*envPath)
	ctx, cancel := context.WithTimeout(context.Background(), env.StatusTimeout())
	defer cancel()
	result, err := app.Status(ctx)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	preview := fs.Bool("preview", false, "select due auths without mutating files or calling upstream")
	apply := fs.Bool("apply", false, "process due auths and persist changes")
	limit := fs.Int("limit", 0, "maximum due auths to process in this run; 0 means no explicit limit")
	_ = fs.Parse(args)

	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	if err := validateScanLimit(applyMode, *limit); err != nil {
		fatalErr(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), env.ScanTimeout(*limit, applyMode))
	defer cancel()
	result, err := app.Scan(ctx, applyMode, *limit)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	sourceDir := fs.String("source-dir", "", "directory containing source auth json files")
	preview := fs.Bool("preview", false, "evaluate duplicates and would-import entries only")
	apply := fs.Bool("apply", false, "copy auths into the maintenance pool and write state")
	_ = fs.Parse(args)

	if *sourceDir == "" {
		fatalf("--source-dir is required")
	}
	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	fileCount := countJSONFilesOrZero(*sourceDir)
	ctx, cancel := context.WithTimeout(context.Background(), env.ImportTimeout(fileCount, applyMode))
	defer cancel()
	result, err := app.Import(ctx, *sourceDir, applyMode)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runTakeout(args []string) {
	fs := flag.NewFlagSet("takeout", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	name := fs.String("name", "", "auth file name to take out")
	destDir := fs.String("dest-dir", "", "destination directory; defaults to exported/")
	preview := fs.Bool("preview", false, "show the planned takeout destination only")
	apply := fs.Bool("apply", false, "move the auth out of the maintenance pool")
	_ = fs.Parse(args)

	if *name == "" {
		fatalf("--name is required")
	}
	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	ctx, cancel := context.WithTimeout(context.Background(), env.TakeoutTimeout())
	defer cancel()
	result, err := app.Takeout(ctx, *name, *destDir, applyMode)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func mustLoadApp(envPath string) (*maintpool.App, *maintpool.EnvConfig) {
	if envPath == "" {
		fatalf("--env is required")
	}
	env, err := maintpool.LoadEnvConfig(envPath)
	if err != nil {
		fatalErr(err)
	}
	cfg, err := config.LoadConfigOptional(env.ConfigPath, false)
	if err != nil {
		fatalErr(err)
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	if err := env.ValidateAgainstConfig(cfg); err != nil {
		fatalErr(err)
	}
	return maintpool.NewApp(env, cfg), env
}

func resolveMode(preview, apply bool) bool {
	if preview && apply {
		fatalf("use only one of --preview or --apply")
	}
	return apply
}

func validateScanLimit(apply bool, limit int) error {
	if apply && limit <= 0 {
		return fmt.Errorf("--limit must be > 0 with --apply")
	}
	return nil
}

func countJSONFilesOrZero(root string) int {
	count := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d == nil || d.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Ext(d.Name()), ".json") {
			count++
		}
		return nil
	})
	if err != nil {
		return 0
	}
	return count
}

func printJSON(value any) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatalErr(err)
	}
	_, _ = os.Stdout.Write(append(raw, '\n'))
}

func fatalErr(err error) {
	fatalf("%v", err)
}

func fatalf(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
