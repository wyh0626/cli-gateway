// Package app builds and executes a white-label cli-gateway CLI.
package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wyh0626/cli-gateway/client/internal/api"
	"github.com/wyh0626/cli-gateway/client/internal/branding"
	"github.com/wyh0626/cli-gateway/client/internal/config"
	"github.com/wyh0626/cli-gateway/client/internal/manifest"
	"github.com/wyh0626/cli-gateway/client/internal/oauth"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var version = "0.3.0-dev"

var reservedRoots = map[string]struct{}{
	"login": {}, "logout": {}, "whoami": {}, "config": {}, "update-commands": {},
	"capabilities": {}, "authorize": {}, "disconnect": {}, "version": {}, "help": {}, "completion": {},
}

// IOStreams contains all user-visible input and output.
type IOStreams struct {
	In     io.Reader
	Out    io.Writer
	ErrOut io.Writer
	IsTTY  func() bool
}

// Options are injectable process dependencies.
type Options struct {
	Args                      []string
	Environ                   []string
	IO                        IOStreams
	Brand                     branding.Config
	OpenURL                   func(string) error
	AuthorizationPollInterval time.Duration
}

// ExitError carries the stable process exit code.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

type runtimeOptions struct {
	region  string
	server  string
	output  string
	yes     bool
	verbose bool
}

type factory struct {
	io                        IOStreams
	reader                    *bufio.Reader
	environ                   map[string]string
	config                    config.File
	configPath                string
	cacheRoot                 string
	selection                 config.Selection
	selected                  bool
	token                     string
	envToken                  bool
	invoker                   string
	store                     manifest.Store
	client                    *api.Client
	oauth                     *oauth.Manager
	runtime                   *runtimeOptions
	openURL                   func(string) error
	authorizationPollInterval time.Duration
	brand                     branding.Config
}

// Run executes the CLI and returns its stable process exit code.
func Run(options Options) int {
	normalizeIO(&options.IO)
	root, buildErr := newRoot(options)
	if buildErr != nil {
		renderError(options.IO.ErrOut, buildErr, false)
		return exitCode(buildErr)
	}
	root.SetArgs(options.Args)
	if err := root.Execute(); err != nil {
		verbose, _ := root.Flags().GetBool("verbose")
		renderError(options.IO.ErrOut, err, verbose)
		return exitCode(err)
	}
	return 0
}

func newRoot(options Options) (*cobra.Command, error) {
	environment := environmentMap(options.Environ)
	brand, err := branding.Resolve(options.Brand)
	if err != nil {
		return nil, err
	}
	paths, err := config.DefaultPaths(brand, environment)
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(paths.ConfigDir, "config.yaml")
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	bootstrap := config.ScanBootstrap(options.Args)
	selection, selectionErr := config.Resolve(cfg, bootstrap, environment, brand)
	selected := selectionErr == nil

	runtime := &runtimeOptions{region: bootstrap.Region, server: bootstrap.Server, output: "table"}
	f := &factory{
		io: options.IO, environ: environment, config: cfg, configPath: configPath, cacheRoot: paths.CacheDir,
		reader:    bufio.NewReader(options.IO.In),
		selection: selection, selected: selected, token: strings.TrimSpace(environment[brand.Env("TOKEN")]),
		invoker: strings.ToLower(strings.TrimSpace(environment[brand.Env("INVOKER")])), runtime: runtime,
		openURL: options.OpenURL, authorizationPollInterval: options.AuthorizationPollInterval,
		brand: brand,
	}
	if f.openURL == nil {
		f.openURL = oauth.OpenBrowser
	}
	if f.authorizationPollInterval <= 0 {
		f.authorizationPollInterval = time.Second
	}
	f.envToken = f.token != ""
	if f.invoker != "ai" {
		f.invoker = "human"
	}
	if selected {
		identity := ""
		if f.token == "" {
			identity = "keyring-current"
		}
		f.store = manifest.Store{
			Root: paths.CacheDir, Region: selection.Name, Server: selection.Region.Server,
			Token: f.token, Identity: identity, Invoker: f.invoker,
		}
		f.oauth, err = oauth.NewWithBrand(selection.Region.Server, selection.Region.CAFile, nil, options.IO.Out, brand)
		if err != nil {
			return nil, err
		}
		if err := f.rebuildClient(); err != nil {
			return nil, err
		}
	}

	root := &cobra.Command{
		Use:           brand.Name,
		Short:         brand.DisplayName,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			switch runtime.output {
			case "table", "json", "yaml":
				return nil
			default:
				return &ExitError{Code: 2, Err: fmt.Errorf("invalid output format %q", runtime.output)}
			}
		},
	}
	root.SetIn(options.IO.In)
	root.SetOut(options.IO.Out)
	root.SetErr(options.IO.ErrOut)
	root.PersistentFlags().StringVar(&runtime.region, "region", bootstrap.Region, "target region")
	root.PersistentFlags().StringVar(&runtime.server, "server", bootstrap.Server, "temporary cli-gateway origin")
	root.PersistentFlags().StringVarP(&runtime.output, "output", "o", "table", "output format: table, json, yaml")
	root.PersistentFlags().BoolVar(&runtime.yes, "yes", false, "confirm an operation that requires confirmation")
	root.PersistentFlags().BoolVar(&runtime.verbose, "verbose", false, "show trace identifiers")
	if err := root.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"table", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp)); err != nil {
		return nil, err
	}

	root.AddCommand(
		f.newUpdateCommands(),
		f.newCapabilitiesCommand(),
		f.newConfigCommand(),
		newVersionCommand(options.IO.Out),
		f.newLoginCommand(),
		f.newLogoutCommand(),
		f.newWhoAmICommand(),
		f.newAuthorizeCommand(),
		f.newDisconnectCommand(),
	)
	if selected {
		cached, cacheErr := f.store.Load()
		switch {
		case cacheErr == nil:
			if time.Since(cached.Fetched) > 24*time.Hour {
				refreshed, refreshErr := f.refreshCached(cached)
				if refreshErr != nil {
					fmt.Fprintf(options.IO.ErrOut, "warning: using stale commands fetched at %s for region %s: %v\n", cached.Fetched.Format(time.RFC3339), selection.Name, refreshErr)
				} else {
					cached = refreshed
				}
			}
			if err := f.addDynamicCommands(root, cached.Document); err != nil {
				return nil, err
			}
		case !errors.Is(cacheErr, os.ErrNotExist):
			fmt.Fprintf(options.IO.ErrOut, "warning: ignoring invalid command cache: %v\n", cacheErr)
		}
	}
	return root, nil
}

func (f *factory) refreshCached(cached manifest.Cached) (manifest.Cached, error) {
	if f.token == "" {
		return cached, errors.New("authentication is not loaded; run update-commands after login")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, etag, unchanged, err := f.fetchManifest(ctx, cached.HTTPETag)
	if err != nil {
		return cached, err
	}
	if unchanged {
		cached.Fetched = time.Now().UTC()
		if etag != "" {
			cached.HTTPETag = etag
		}
		if err := f.store.Save(cached); err != nil {
			return manifest.Cached{}, err
		}
		return cached, nil
	}
	document, err := manifest.Parse(body)
	if err != nil {
		return cached, err
	}
	if err := validateDynamicRoots(document, f.brand.Name); err != nil {
		return cached, err
	}
	cached = manifest.Cached{
		HTTPETag: etag, Fetched: time.Now().UTC(), Server: f.selection.Region.Server, Document: document,
	}
	if err := f.store.Save(cached); err != nil {
		return manifest.Cached{}, err
	}
	return cached, nil
}

func (f *factory) newUpdateCommands() *cobra.Command {
	return &cobra.Command{
		Use:   "update-commands",
		Short: "Fetch the command manifest for the current identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cached, unchanged, err := f.syncCommands(cmd.Context())
			if err != nil {
				return err
			}
			if unchanged {
				fmt.Fprintf(f.io.Out, "commands are current for region %s\n", f.selection.Name)
				return nil
			}
			fmt.Fprintf(f.io.Out, "updated %d domain(s) for region %s; rerun %s to use them\n", len(cached.Document.Domains), f.selection.Name, f.brand.Name)
			return nil
		},
	}
}

func (f *factory) newCapabilitiesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities",
		Short: "Describe commands available to the current identity",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cached, _, err := f.syncCommands(cmd.Context())
			if err != nil {
				return err
			}
			return writeCapabilities(f.io.Out, f.runtime.output, f.brand.Name, cached.Document)
		},
	}
}

func (f *factory) syncCommands(ctx context.Context) (manifest.Cached, bool, error) {
	if !f.selected {
		return manifest.Cached{}, false, &ExitError{Code: 2, Err: errors.New("no target server selected; configure a region or use --server")}
	}
	if err := f.ensureToken(ctx); err != nil {
		return manifest.Cached{}, false, &ExitError{Code: 3, Err: err}
	}
	old, _ := f.store.Load()
	body, etag, unchanged, err := f.fetchManifest(ctx, old.HTTPETag)
	if err != nil {
		return manifest.Cached{}, false, classify(err)
	}
	now := time.Now().UTC()
	if unchanged {
		if old.Document.CLI.Name == "" {
			return manifest.Cached{}, false, &ExitError{Code: 4, Err: errors.New("server returned 304 without a usable local cache")}
		}
		old.Fetched = now
		if etag != "" {
			old.HTTPETag = etag
		}
		if err := f.store.Save(old); err != nil {
			return manifest.Cached{}, false, err
		}
		return old, true, nil
	}
	document, err := manifest.Parse(body)
	if err != nil {
		return manifest.Cached{}, false, &ExitError{Code: 4, Err: err}
	}
	if err := validateDynamicRoots(document, f.brand.Name); err != nil {
		return manifest.Cached{}, false, &ExitError{Code: 4, Err: err}
	}
	cached := manifest.Cached{
		HTTPETag: etag, Fetched: now, Server: f.selection.Region.Server, Document: document,
	}
	if err := f.store.Save(cached); err != nil {
		return manifest.Cached{}, false, err
	}
	return cached, false, nil
}

func (f *factory) rebuildClient() error {
	if !f.selected {
		return errors.New("no target server selected")
	}
	client, err := api.New(api.Options{
		Server: f.selection.Region.Server, Token: f.token, Invoker: f.invoker,
		CAFile: f.selection.Region.CAFile, UserAgent: f.brand.UserAgent + "/" + version,
	})
	if err != nil {
		return err
	}
	f.client = client
	return nil
}

func (f *factory) ensureToken(ctx context.Context) error {
	if f.token != "" {
		return nil
	}
	if !f.selected || f.oauth == nil {
		return errors.New("no target server selected")
	}
	token, err := f.oauth.AccessToken(ctx)
	if err != nil {
		return err
	}
	f.token = token
	return f.rebuildClient()
}

func (f *factory) newLoginCommand() *cobra.Command {
	var device bool
	var scopes []string
	command := &cobra.Command{
		Use: "login", Short: "Log in through the configured authorization server", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !f.selected || f.oauth == nil {
				return &ExitError{Code: 2, Err: errors.New("no target server selected")}
			}
			var token oauth.Token
			var err error
			if device {
				token, err = f.oauth.LoginDevice(cmd.Context(), scopes)
			} else {
				token, err = f.oauth.LoginPKCE(cmd.Context(), scopes)
			}
			if err != nil {
				return &ExitError{Code: 3, Err: err}
			}
			f.token = token.AccessToken
			f.envToken = false
			if err := f.rebuildClient(); err != nil {
				return err
			}
			_ = f.store.Remove()
			fmt.Fprintf(f.io.Out, "logged in to region %s; refresh token stored in OS keyring\n", f.selection.Name)
			cached, _, syncErr := f.syncCommands(cmd.Context())
			if syncErr != nil {
				fmt.Fprintf(f.io.ErrOut, "warning: login succeeded but commands could not be loaded: %v\n", syncErr)
			} else {
				fmt.Fprintf(f.io.Out, "%d command domain(s) are ready\n", len(cached.Document.Domains))
			}
			return nil
		},
	}
	command.Flags().BoolVar(&device, "device", false, "use OAuth device authorization instead of browser PKCE")
	command.Flags().StringSliceVar(&scopes, "scope", nil, "OAuth scopes (repeat or comma-separate)")
	return command
}

func (f *factory) newLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use: "logout", Short: "Revoke and remove the current refresh token", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !f.selected || f.oauth == nil {
				return &ExitError{Code: 2, Err: errors.New("no target server selected")}
			}
			err := f.oauth.Logout(cmd.Context())
			_ = f.store.Remove()
			if err != nil {
				return &ExitError{Code: 3, Err: err}
			}
			fmt.Fprintf(f.io.Out, "logged out of region %s\n", f.selection.Name)
			return nil
		},
	}
}

func (f *factory) newAuthorizeCommand() *cobra.Command {
	return &cobra.Command{
		Use: "authorize DOMAIN", Short: "Authorize one downstream service for the current user", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !f.selected {
				return &ExitError{Code: 2, Err: errors.New("no target server selected")}
			}
			if err := f.ensureToken(cmd.Context()); err != nil {
				return &ExitError{Code: 3, Err: err}
			}
			if err := f.authorizeDownstream(cmd.Context(), args[0]); err != nil {
				return classify(err)
			}
			return nil
		},
	}
}

func (f *factory) newDisconnectCommand() *cobra.Command {
	return &cobra.Command{
		Use: "disconnect DOMAIN", Short: "Remove the current user's downstream authorization", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !f.selected {
				return &ExitError{Code: 2, Err: errors.New("no target server selected")}
			}
			if err := f.ensureToken(cmd.Context()); err != nil {
				return &ExitError{Code: 3, Err: err}
			}
			if err := f.disconnectDownstreamAuthorization(cmd.Context(), args[0]); err != nil {
				return classify(err)
			}
			fmt.Fprintf(f.io.Out, "removed downstream authorization for %s\n", args[0])
			return nil
		},
	}
}

func (f *factory) newWhoAmICommand() *cobra.Command {
	return &cobra.Command{
		Use: "whoami", Short: "Show the authenticated gateway identity", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := f.ensureToken(cmd.Context()); err != nil {
				return &ExitError{Code: 3, Err: err}
			}
			body, err := f.whoAmI(cmd.Context())
			if err != nil {
				return classify(err)
			}
			var pretty bytes.Buffer
			if json.Indent(&pretty, body, "", "  ") != nil {
				_, err = f.io.Out.Write(body)
				return err
			}
			_, err = fmt.Fprintln(f.io.Out, pretty.String())
			return err
		},
	}
}

func (f *factory) newConfigCommand() *cobra.Command {
	command := &cobra.Command{Use: "config", Short: "Manage regions"}
	command.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List configured regions",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			for _, name := range config.SortedRegionNames(f.config) {
				region := f.config.Regions[name]
				marker := " "
				if name == f.config.CurrentRegion {
					marker = "*"
				}
				fmt.Fprintf(f.io.Out, "%s %s\t%s\t%s\n", marker, name, region.DisplayName, region.Server)
			}
			return nil
		},
	})
	command.AddCommand(&cobra.Command{
		Use:   "use-region NAME",
		Short: "Select the default region",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, ok := f.config.Regions[args[0]]; !ok {
				return &ExitError{Code: 2, Err: fmt.Errorf("region %q is not configured", args[0])}
			}
			f.config.CurrentRegion = args[0]
			return config.Save(f.configPath, f.config)
		},
	})
	var displayName string
	var caFile string
	add := &cobra.Command{
		Use:   "add-region NAME SERVER",
		Short: "Add or replace a region",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			origin, err := config.ValidateOrigin(args[1])
			if err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			region := config.Region{Server: origin, DisplayName: displayName, CAFile: caFile}
			if err := config.ValidateRegion(args[0], region); err != nil {
				return &ExitError{Code: 2, Err: err}
			}
			if f.config.Regions == nil {
				f.config.Regions = make(map[string]config.Region)
			}
			f.config.Regions[args[0]] = region
			if f.config.CurrentRegion == "" {
				f.config.CurrentRegion = args[0]
			}
			return config.Save(f.configPath, f.config)
		},
	}
	add.Flags().StringVar(&displayName, "display-name", "", "human-readable region name")
	add.Flags().StringVar(&caFile, "ca-file", "", "private CA bundle")
	command.AddCommand(add)
	return command
}

func newVersionCommand(out io.Writer) *cobra.Command {
	return &cobra.Command{
		Use: "version", Args: cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) { fmt.Fprintln(out, version) },
	}
}

func (f *factory) addDynamicCommands(root *cobra.Command, document manifest.Document) error {
	if err := validateDynamicRoots(document, f.brand.Name); err != nil {
		return err
	}
	for _, domain := range document.Domains {
		domainCommand := &cobra.Command{Use: domain.Name, Short: "Commands for " + domain.Name}
		nodes := map[string]*cobra.Command{"": domainCommand}
		for _, definition := range domain.Commands {
			var parent = domainCommand
			var prefix []string
			for index, segment := range definition.Path {
				prefix = append(prefix, segment)
				key := strings.Join(prefix, ".")
				node, ok := nodes[key]
				if !ok {
					node = &cobra.Command{Use: segment}
					parent.AddCommand(node)
					nodes[key] = node
				}
				if index == len(definition.Path)-1 {
					if node.RunE != nil {
						return fmt.Errorf("manifest contains duplicate command %s.%s", domain.Name, key)
					}
					if err := f.configureLeaf(node, domain.Name, definition); err != nil {
						return err
					}
				}
				parent = node
			}
		}
		root.AddCommand(domainCommand)
	}
	return nil
}

func (f *factory) configureLeaf(command *cobra.Command, domain string, definition manifest.Command) error {
	command.Short = definition.Summary
	command.Args = cobra.NoArgs
	for _, flag := range definition.Flags {
		switch flag.Type {
		case "string":
			command.Flags().String(flag.Name, stringDefault(flag.Default), flag.Description)
		case "int":
			command.Flags().Int(flag.Name, intDefault(flag.Default), flag.Description)
		case "bool":
			command.Flags().Bool(flag.Name, boolDefault(flag.Default), flag.Description)
		case "stringArray":
			command.Flags().StringArray(flag.Name, stringArrayDefault(flag.Default), flag.Description)
		default:
			return fmt.Errorf("command %s has unsupported flag type %q", command.CommandPath(), flag.Type)
		}
	}
	command.RunE = func(cmd *cobra.Command, _ []string) error {
		if err := f.promptMissingFlags(cmd, definition.Flags); err != nil {
			return err
		}
		if err := f.ensureToken(cmd.Context()); err != nil {
			return &ExitError{Code: 3, Err: err}
		}
		args, err := commandArguments(cmd, definition.Flags)
		if err != nil {
			return &ExitError{Code: 2, Err: err}
		}
		confirmed, err := f.confirm(cmd, domain, definition, args)
		if err != nil {
			return err
		}
		if definition.Streaming {
			stream, streamErr := f.executeStream(cmd.Context(), domain, strings.Join(definition.Path, "."), args, confirmed)
			if streamErr != nil {
				return classify(streamErr)
			}
			defer stream.Body.Close()
			_, streamErr = io.Copy(f.io.Out, stream.Body)
			return streamErr
		}
		raw, err := f.execute(cmd.Context(), domain, strings.Join(definition.Path, "."), args, confirmed)
		if err != nil {
			return classify(err)
		}
		if err := writeOutput(f.io.Out, f.runtime.output, raw); err != nil {
			return err
		}
		return f.handleUserAction(raw)
	}
	return nil
}

func (f *factory) fetchManifest(ctx context.Context, etag string) ([]byte, string, bool, error) {
	body, responseETag, unchanged, err := f.client.Manifest(ctx, etag)
	if !isExpiredAuth(err) || f.envToken {
		return body, responseETag, unchanged, err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return nil, "", false, refreshErr
	}
	return f.client.Manifest(ctx, etag)
}

func (f *factory) whoAmI(ctx context.Context) ([]byte, error) {
	body, err := f.client.WhoAmI(ctx)
	if !isExpiredAuth(err) || f.envToken {
		return body, err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return nil, refreshErr
	}
	return f.client.WhoAmI(ctx)
}

func (f *factory) execute(ctx context.Context, domain, command string, args map[string]any, confirmed bool) ([]byte, error) {
	body, err := f.executeOnce(ctx, domain, command, args, confirmed)
	if !isDownstreamAuthorizationRequired(err) || !f.io.IsTTY() {
		return body, err
	}
	if authorizeErr := f.authorizeDownstream(ctx, domain); authorizeErr != nil {
		return nil, authorizeErr
	}
	return f.executeOnce(ctx, domain, command, args, confirmed)
}

func (f *factory) executeOnce(ctx context.Context, domain, command string, args map[string]any, confirmed bool) ([]byte, error) {
	body, err := f.client.Execute(ctx, domain, command, args, confirmed)
	if !isExpiredAuth(err) || f.envToken {
		return body, err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return nil, refreshErr
	}
	return f.client.Execute(ctx, domain, command, args, confirmed)
}

func (f *factory) executeStream(ctx context.Context, domain, command string, args map[string]any, confirmed bool) (*api.Stream, error) {
	stream, err := f.executeStreamOnce(ctx, domain, command, args, confirmed)
	if !isDownstreamAuthorizationRequired(err) || !f.io.IsTTY() {
		return stream, err
	}
	if authorizeErr := f.authorizeDownstream(ctx, domain); authorizeErr != nil {
		return nil, authorizeErr
	}
	return f.executeStreamOnce(ctx, domain, command, args, confirmed)
}

func (f *factory) executeStreamOnce(ctx context.Context, domain, command string, args map[string]any, confirmed bool) (*api.Stream, error) {
	stream, err := f.client.ExecuteStream(ctx, domain, command, args, confirmed)
	if !isExpiredAuth(err) || f.envToken {
		return stream, err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return nil, refreshErr
	}
	return f.client.ExecuteStream(ctx, domain, command, args, confirmed)
}

func (f *factory) authorizeDownstream(ctx context.Context, domain string) error {
	start, err := f.beginDownstreamAuthorization(ctx, domain)
	if err != nil {
		return err
	}
	fmt.Fprintf(f.io.Out, "Open this URL to authorize %s:\n%s\n", domain, start.AuthorizationURL)
	if err := f.openURL(start.AuthorizationURL); err != nil {
		fmt.Fprintf(f.io.ErrOut, "warning: could not open browser automatically: %v\n", err)
	}
	deadline := start.ExpiresAt
	if deadline.IsZero() || deadline.After(time.Now().Add(15*time.Minute)) {
		deadline = time.Now().Add(5 * time.Minute)
	}
	for {
		if !time.Now().Before(deadline) {
			return errors.New("downstream authorization expired")
		}
		timer := time.NewTimer(f.authorizationPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		status, statusErr := f.downstreamAuthorizationStatus(ctx, domain)
		if statusErr != nil {
			return statusErr
		}
		if status.Authorized {
			fmt.Fprintf(f.io.Out, "authorized downstream service %s\n", domain)
			return nil
		}
	}
}

func (f *factory) beginDownstreamAuthorization(ctx context.Context, domain string) (api.DownstreamAuthorizationStart, error) {
	start, err := f.client.BeginDownstreamAuthorization(ctx, domain)
	if !isExpiredAuth(err) || f.envToken {
		return start, err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return api.DownstreamAuthorizationStart{}, refreshErr
	}
	return f.client.BeginDownstreamAuthorization(ctx, domain)
}

func (f *factory) downstreamAuthorizationStatus(ctx context.Context, domain string) (api.DownstreamAuthorizationStatus, error) {
	status, err := f.client.DownstreamAuthorizationStatus(ctx, domain)
	if !isExpiredAuth(err) || f.envToken {
		return status, err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return api.DownstreamAuthorizationStatus{}, refreshErr
	}
	return f.client.DownstreamAuthorizationStatus(ctx, domain)
}

func (f *factory) disconnectDownstreamAuthorization(ctx context.Context, domain string) error {
	err := f.client.DisconnectDownstreamAuthorization(ctx, domain)
	if !isExpiredAuth(err) || f.envToken {
		return err
	}
	if refreshErr := f.refreshAfterExpiry(ctx); refreshErr != nil {
		return refreshErr
	}
	return f.client.DisconnectDownstreamAuthorization(ctx, domain)
}

func (f *factory) refreshAfterExpiry(ctx context.Context) error {
	if f.oauth == nil {
		return errors.New("access token expired and no OAuth session is available")
	}
	token, err := f.oauth.RefreshAccessToken(ctx)
	if err != nil {
		return fmt.Errorf("refresh expired access token: %w", err)
	}
	f.token = token
	return f.rebuildClient()
}

func isExpiredAuth(err error) bool {
	var apiErr *api.Error
	return errors.As(err, &apiErr) && apiErr.Code == "E_AUTH_EXPIRED"
}

func isDownstreamAuthorizationRequired(err error) bool {
	var apiErr *api.Error
	return errors.As(err, &apiErr) && apiErr.Code == "E_DOWNSTREAM_AUTH_REQUIRED"
}

func (f *factory) confirm(cmd *cobra.Command, domain string, definition manifest.Command, args map[string]any) (bool, error) {
	if definition.Risk != "write" && definition.Risk != "destroy" {
		return false, nil
	}
	fmt.Fprintf(f.io.ErrOut, "▸ region: %s", f.selection.Name)
	if f.selection.Region.DisplayName != "" {
		fmt.Fprintf(f.io.ErrOut, "（%s）", f.selection.Region.DisplayName)
	}
	fmt.Fprintf(f.io.ErrOut, " · %s\n", f.selection.Region.Server)
	if !definition.Confirm && definition.Risk != "destroy" {
		return false, nil
	}
	if f.runtime.yes {
		return true, nil
	}
	if !f.io.IsTTY() {
		return false, &ExitError{Code: 2, Err: errors.New("E_CONFIRM_REQUIRED: command requires --yes when stdin is not a TTY")}
	}
	if len(args) > 0 {
		encoded, _ := json.MarshalIndent(args, "", "  ")
		fmt.Fprintf(f.io.ErrOut, "request preview:\n%s\n", encoded)
	}
	target, _ := url.Parse(f.selection.Region.Server)
	phrase := strings.Join(append([]string{domain}, definition.Path...), ".") + " " + f.selection.Name + " " + target.Host
	fmt.Fprintf(f.io.ErrOut, "type %q to confirm: ", phrase)
	answer, err := f.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, &ExitError{Code: 5, Err: fmt.Errorf("confirmation cancelled: %w", err)}
	}
	if strings.TrimSpace(answer) != phrase {
		return false, &ExitError{Code: 5, Err: errors.New("confirmation cancelled")}
	}
	_ = cmd
	return true, nil
}

func (f *factory) promptMissingFlags(command *cobra.Command, flags []manifest.Flag) error {
	for _, definition := range flags {
		if !definition.Required || command.Flags().Changed(definition.Name) || definition.Default != nil {
			continue
		}
		if !f.io.IsTTY() {
			return &ExitError{Code: 2, Err: fmt.Errorf("required flag --%s was not provided", definition.Name)}
		}
		label := strings.TrimSpace(definition.Description)
		if label == "" {
			label = definition.Name
		}
		fmt.Fprintf(f.io.ErrOut, "? %s (--%s): ", label, definition.Name)
		answer, err := f.reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return &ExitError{Code: 5, Err: fmt.Errorf("read --%s: %w", definition.Name, err)}
		}
		answer = strings.TrimSpace(answer)
		if answer == "" {
			return &ExitError{Code: 2, Err: fmt.Errorf("required flag --%s cannot be empty", definition.Name)}
		}
		if err := command.Flags().Set(definition.Name, answer); err != nil {
			return &ExitError{Code: 2, Err: fmt.Errorf("invalid --%s: %w", definition.Name, err)}
		}
	}
	return nil
}

func (f *factory) handleUserAction(raw []byte) error {
	type userAction struct {
		Type              string `json:"type"`
		URL               string `json:"url"`
		Message           string `json:"message"`
		CompletionCommand string `json:"completionCommand"`
	}
	type actionContainer struct {
		UserAction *userAction     `json:"userAction"`
		Data       json.RawMessage `json:"data"`
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || len(envelope.Data) == 0 {
		return nil
	}
	var action *userAction
	next := envelope.Data
	for depth := 0; depth < 3 && len(next) > 0; depth++ {
		var container actionContainer
		if err := json.Unmarshal(next, &container); err != nil {
			return nil
		}
		if container.UserAction != nil {
			action = container.UserAction
			break
		}
		next = container.Data
	}
	if action == nil {
		return nil
	}
	if action.Type != "open_url" {
		fmt.Fprintf(f.io.ErrOut, "ignored unsupported user action %q\n", action.Type)
		return nil
	}
	target, err := url.Parse(strings.TrimSpace(action.URL))
	if err != nil || target.Scheme != "https" || target.Host == "" || target.User != nil {
		fmt.Fprintln(f.io.ErrOut, "ignored unsafe browser action returned by the backend")
		return nil
	}
	message := strings.TrimSpace(action.Message)
	if message != "" {
		fmt.Fprintf(f.io.ErrOut, "\n%s\n", message)
	}
	if !f.io.IsTTY() {
		fmt.Fprintf(f.io.ErrOut, "Open this URL in a browser to continue:\n%s\n", target.String())
		f.printCompletionCommand(action.CompletionCommand)
		return nil
	}
	fmt.Fprintf(f.io.ErrOut, "Open downstream authorization at %s in your browser? [y/N]: ", target.Host)
	answer, readErr := f.reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		fmt.Fprintf(f.io.ErrOut, "Could not read browser confirmation; open manually:\n%s\n", target.String())
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(answer), "y") || strings.EqualFold(strings.TrimSpace(answer), "yes") {
		if openErr := f.openURL(target.String()); openErr != nil {
			fmt.Fprintf(f.io.ErrOut, "Could not open the browser; open manually:\n%s\n", target.String())
		}
	} else {
		fmt.Fprintf(f.io.ErrOut, "Open manually when ready:\n%s\n", target.String())
	}
	f.printCompletionCommand(action.CompletionCommand)
	return nil
}

func (f *factory) printCompletionCommand(command string) {
	command = strings.TrimSpace(command)
	if command == "" || len(command) > 512 || strings.ContainsAny(command, "\r\n") {
		return
	}
	fmt.Fprintf(f.io.ErrOut, "After authorization, check the application with:\n%s\n", command)
}

func commandArguments(command *cobra.Command, flags []manifest.Flag) (map[string]any, error) {
	result := make(map[string]any)
	for _, definition := range flags {
		changed := command.Flags().Changed(definition.Name)
		if !changed && definition.Default == nil {
			continue
		}
		var value any
		var err error
		switch definition.Type {
		case "string":
			value, err = command.Flags().GetString(definition.Name)
		case "int":
			value, err = command.Flags().GetInt(definition.Name)
		case "bool":
			value, err = command.Flags().GetBool(definition.Name)
		case "stringArray":
			value, err = command.Flags().GetStringArray(definition.Name)
		}
		if err != nil {
			return nil, err
		}
		result[definition.Name] = value
	}
	return result, nil
}

func writeOutput(out io.Writer, format string, raw []byte) error {
	switch format {
	case "json":
		_, err := fmt.Fprintln(out, strings.TrimSpace(string(raw)))
		return err
	case "yaml":
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		data, err := yaml.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode YAML: %w", err)
		}
		_, err = out.Write(data)
		return err
	case "table":
		var envelope struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if len(envelope.Data) == 0 {
			return errors.New("response is missing data")
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, envelope.Data, "", "  "); err != nil {
			return fmt.Errorf("format response data: %w", err)
		}
		_, err := fmt.Fprintln(out, pretty.String())
		return err
	default:
		return &ExitError{Code: 2, Err: fmt.Errorf("invalid output format %q", format)}
	}
}

func writeCapabilities(out io.Writer, format, cliName string, document manifest.Document) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(document, "", "  ")
		if err != nil {
			return fmt.Errorf("encode capabilities: %w", err)
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	case "yaml":
		data, err := yaml.Marshal(document)
		if err != nil {
			return fmt.Errorf("encode capabilities: %w", err)
		}
		_, err = out.Write(data)
		return err
	case "table":
		fmt.Fprintln(out, "COMMAND\tRISK\tCONFIRM\tSUMMARY")
		for _, domain := range document.Domains {
			for _, command := range domain.Commands {
				name := strings.Join(append([]string{cliName, domain.Name}, command.Path...), " ")
				fmt.Fprintf(out, "%s\t%s\t%t\t%s\n", name, command.Risk, command.Confirm, command.Summary)
			}
		}
		return nil
	default:
		return &ExitError{Code: 2, Err: fmt.Errorf("invalid output format %q", format)}
	}
}

func validateDynamicRoots(document manifest.Document, cliName string) error {
	if document.CLI.Name != cliName {
		return fmt.Errorf("manifest cli.name %q does not match this %q client", document.CLI.Name, cliName)
	}
	seen := make(map[string]struct{})
	for _, domain := range document.Domains {
		if _, reserved := reservedRoots[domain.Name]; reserved {
			return fmt.Errorf("manifest domain %q conflicts with a built-in command", domain.Name)
		}
		if _, duplicate := seen[domain.Name]; duplicate {
			return fmt.Errorf("manifest contains duplicate domain %q", domain.Name)
		}
		seen[domain.Name] = struct{}{}
	}
	return nil
}

func classify(err error) error {
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return err
	}
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "E_AUTH_MISSING", "E_AUTH_INVALID", "E_AUTH_EXPIRED":
			return &ExitError{Code: 3, Err: err}
		case "E_ARG_INVALID", "E_CMD_NOT_FOUND", "E_CONFIRM_REQUIRED":
			return &ExitError{Code: 2, Err: err}
		default:
			return &ExitError{Code: 4, Err: err}
		}
	}
	return &ExitError{Code: 4, Err: err}
}

func exitCode(err error) int {
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return 2
}

func renderError(out io.Writer, err error, verbose bool) {
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		fmt.Fprintf(out, "error: %s\n", apiErr.Error())
		if verbose && apiErr.TraceID != "" {
			fmt.Fprintf(out, "trace: %s\n", apiErr.TraceID)
		}
		return
	}
	fmt.Fprintf(out, "error: %s\n", err)
}

func normalizeIO(streams *IOStreams) {
	if streams.In == nil {
		streams.In = os.Stdin
	}
	if streams.Out == nil {
		streams.Out = os.Stdout
	}
	if streams.ErrOut == nil {
		streams.ErrOut = os.Stderr
	}
	if streams.IsTTY == nil {
		streams.IsTTY = func() bool {
			file, ok := streams.In.(*os.File)
			if !ok {
				return false
			}
			return isTerminal(file)
		}
	}
}

func environmentMap(values []string) map[string]string {
	result := make(map[string]string)
	for _, value := range values {
		key, raw, ok := strings.Cut(value, "=")
		if ok {
			result[key] = raw
		}
	}
	return result
}

func stringDefault(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func intDefault(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case json.Number:
		result, _ := strconv.Atoi(typed.String())
		return result
	case int:
		return typed
	default:
		result, _ := strconv.Atoi(fmt.Sprint(value))
		return result
	}
}

func boolDefault(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	default:
		result, _ := strconv.ParseBool(fmt.Sprint(value))
		return result
	}
}

func stringArrayDefault(value any) []string {
	values, ok := value.([]any)
	if !ok {
		if typed, ok := value.([]string); ok {
			return typed
		}
		return nil
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		result = append(result, fmt.Sprint(item))
	}
	return result
}
