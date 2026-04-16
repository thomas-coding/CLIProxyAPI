package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/reserve2"
)

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: %s <sample|sync|status> [flags]", os.Args[0])
	}
	switch os.Args[1] {
	case "sample":
		runSample(os.Args[2:])
	case "sync":
		runSync(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
}

func runSample(args []string) {
	fs := flag.NewFlagSet("sample", flag.ExitOnError)
	envPath := fs.String("env", "", "path to reserve2 env file")
	preview := fs.Bool("preview", false, "run without mutating files")
	apply := fs.Bool("apply", false, "apply changes")
	_ = fs.Parse(args)

	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	ctx, cancel := context.WithTimeout(context.Background(), env.SampleTimeout(applyMode))
	defer cancel()
	result, err := app.Sample(ctx, applyMode)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runSync(args []string) {
	fs := flag.NewFlagSet("sync", flag.ExitOnError)
	envPath := fs.String("env", "", "path to reserve2 env file")
	preview := fs.Bool("preview", false, "run without mutating files")
	apply := fs.Bool("apply", false, "apply changes")
	_ = fs.Parse(args)

	app, env := mustLoadApp(*envPath)
	applyMode := resolveMode(*preview, *apply)
	ctx, cancel := context.WithTimeout(context.Background(), env.SyncTimeout(applyMode))
	defer cancel()
	result, err := app.Sync(ctx, applyMode)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	envPath := fs.String("env", "", "path to reserve2 env file")
	_ = fs.Parse(args)

	app, _ := mustLoadApp(*envPath)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := app.Status(ctx)
	if err != nil {
		fatalErr(err)
	}
	printJSON(result)
}

func mustLoadApp(envPath string) (*reserve2.App, *reserve2.EnvConfig) {
	if envPath == "" {
		fatalf("--env is required")
	}
	env, err := reserve2.LoadEnvConfig(envPath)
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
	return reserve2.NewApp(env, cfg), env
}

func resolveMode(preview, apply bool) bool {
	if preview && apply {
		fatalf("use only one of --preview or --apply")
	}
	return apply
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
