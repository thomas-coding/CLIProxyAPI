package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/maintpool"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: %s <status|scan|import|assign-lanes|adopt-legacy|clear-emergency-stop|takeout> [flags]", os.Args[0])
	}
	switch os.Args[1] {
	case "status":
		runStatus(os.Args[2:])
	case "scan":
		runScan(os.Args[2:])
	case "import":
		runImport(os.Args[2:])
	case "assign-lanes":
		runAssignLanes(os.Args[2:])
	case "adopt-legacy":
		runAdoptLegacy(os.Args[2:])
	case "clear-emergency-stop":
		runClearEmergencyStop(os.Args[2:])
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
	cohortID := fs.String("cohort-id", "", "logical cohort id for imported auths")
	sourceBatchID := fs.String("source-batch-id", "", "source batch id for imported auths")
	lane := fs.String("lane", "", "initial lane; supported value for import is baseline_pending")
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
	result, err := app.Import(ctx, *sourceDir, maintpool.ImportOptions{
		Apply:         applyMode,
		CohortID:      *cohortID,
		SourceBatchID: *sourceBatchID,
		Lane:          *lane,
	})
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runAssignLanes(args []string) {
	fs := flag.NewFlagSet("assign-lanes", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	cohortID := fs.String("cohort-id", "", "logical cohort id to assign")
	guard0 := fs.Int("guard-0", 0, "number of ready auths to assign into guard_0")
	guard1 := fs.Int("guard-1", 0, "number of ready auths to assign into guard_1")
	guard2 := fs.Int("guard-2", 0, "number of ready auths to assign into guard_2")
	preview := fs.Bool("preview", false, "show lane assignment plan without mutating state")
	apply := fs.Bool("apply", false, "persist lane assignment into state")
	_ = fs.Parse(args)

	if strings.TrimSpace(*cohortID) == "" {
		fatalf("--cohort-id is required")
	}
	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	ctx, cancel := context.WithTimeout(context.Background(), env.TakeoutTimeout())
	defer cancel()
	result, err := app.AssignLanes(ctx, maintpool.AssignLanesOptions{
		Apply:    applyMode,
		CohortID: *cohortID,
		Guard0:   *guard0,
		Guard1:   *guard1,
		Guard2:   *guard2,
	})
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runAdoptLegacy(args []string) {
	fs := flag.NewFlagSet("adopt-legacy", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	cohortID := fs.String("cohort-id", "", "logical cohort id to assign")
	sourceBatchID := fs.String("source-batch-id", "", "source batch id to stamp onto adopted legacy auths")
	guard0 := fs.Int("guard-0", 0, "number of eligible legacy auths to assign into guard_0")
	guard1 := fs.Int("guard-1", 0, "number of eligible legacy auths to assign into guard_1")
	guard2 := fs.Int("guard-2", 0, "number of eligible legacy auths to assign into guard_2")
	requireLastRefreshWithin := fs.Duration("require-last-refresh-within", 72*time.Hour, "only legacy auths with recent last_refresh_ok_at inside this window are eligible")
	preview := fs.Bool("preview", false, "show adoption plan without mutating state")
	apply := fs.Bool("apply", false, "persist cohort/lane metadata onto eligible legacy auths")
	_ = fs.Parse(args)

	if strings.TrimSpace(*cohortID) == "" {
		fatalf("--cohort-id is required")
	}
	if strings.TrimSpace(*sourceBatchID) == "" {
		fatalf("--source-batch-id is required")
	}
	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	ctx, cancel := context.WithTimeout(context.Background(), env.TakeoutTimeout())
	defer cancel()
	result, err := app.AdoptLegacy(ctx, maintpool.AdoptLegacyOptions{
		Apply:                    applyMode,
		CohortID:                 *cohortID,
		SourceBatchID:            *sourceBatchID,
		Guard0:                   *guard0,
		Guard1:                   *guard1,
		Guard2:                   *guard2,
		RequireLastRefreshWithin: *requireLastRefreshWithin,
	})
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runClearEmergencyStop(args []string) {
	fs := flag.NewFlagSet("clear-emergency-stop", flag.ExitOnError)
	envPath := fs.String("env", "", "path to maintpool env file")
	reason := fs.String("reason", "", "operator note explaining why the stop is being cleared")
	preview := fs.Bool("preview", false, "show current emergency-stop state only")
	apply := fs.Bool("apply", false, "clear the persisted emergency-stop marker")
	_ = fs.Parse(args)

	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	if applyMode && strings.TrimSpace(*reason) == "" {
		fatalf("--reason is required with --apply")
	}
	ctx, cancel := context.WithTimeout(context.Background(), env.TakeoutTimeout())
	defer cancel()
	result, err := app.ClearEmergencyStop(ctx, *reason, applyMode)
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
