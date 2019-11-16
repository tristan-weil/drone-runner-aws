// Copyright 2019 Drone.IO Inc. All rights reserved.
// Use of this source code is governed by the Polyform License
// that can be found in the LICENSE file.

package command

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/drone/drone-go/drone"
	"github.com/drone/envsubst"
	"github.com/drone/runner-go/environ"
	"github.com/drone/runner-go/logger"
	"github.com/drone/runner-go/manifest"
	"github.com/drone/runner-go/pipeline"
	"github.com/drone/runner-go/pipeline/console"
	"github.com/drone/runner-go/secret"
	"github.com/drone/signal"
	"github.com/tristan-weil/drone-runner-aws/command/internal"
	"github.com/tristan-weil/drone-runner-aws/engine"
	"github.com/tristan-weil/drone-runner-aws/engine/compiler"
	"github.com/tristan-weil/drone-runner-aws/engine/resource"
	"github.com/tristan-weil/drone-runner-aws/runtime"

	"github.com/mattn/go-isatty"
	"github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

type execCommand struct {
	*internal.Flags

	Source  *os.File
	Environ map[string]string
	Secrets map[string]string
	Pretty  bool
	Procs   int64
	Debug   bool
	Trace   bool
	Dump    bool

	AWS struct {
		SSHPrivateKey   string `envconfig:"DRONE_PRIVATE_KEY_FILE"`
		Endpoint        string `envconfig:"AWS_ENDPOINT"`
		Region          string `envconfig:"AWS_DEFAULT_REGION"`
		AccessKeyID     string `envconfig:"AWS_ACCESS_KEY_ID"`
		SecretAccessKey string `envconfig:"AWS_SECRET_ACCESS_KEY"`
	}
}

func (c *execCommand) run(*kingpin.ParseContext) error {
	rawsource, err := ioutil.ReadAll(c.Source)
	if err != nil {
		return err
	}

	envs := environ.Combine(
		c.Environ,
		environ.System(c.System),
		environ.Repo(c.Repo),
		environ.Build(c.Build),
		environ.Stage(c.Stage),
		environ.Link(c.Repo, c.Build, c.System),
		c.Build.Params,
	)

	// string substitution function ensures that string
	// replacement variables are escaped and quoted if they
	// contain newlines.
	subf := func(k string) string {
		v := envs[k]
		if strings.Contains(v, "\n") {
			v = fmt.Sprintf("%q", v)
		}
		return v
	}

	// evaluates string replacement expressions and returns an
	// update configuration.
	config, err := envsubst.Eval(string(rawsource), subf)
	if err != nil {
		return err
	}

	// parse and lint the configuration.
	manifest, err := manifest.ParseString(config)
	if err != nil {
		return err
	}

	// a configuration can contain multiple pipelines.
	// get a specific pipeline resource for execution.
	resource, err := resource.Lookup(c.Stage.Name, manifest)
	if err != nil {
		return err
	}

	// compile the pipeline to an intermediate representation.
	comp := &compiler.Compiler{
		Pipeline: resource,
		Manifest: manifest,
		Build:    c.Build,
		Netrc:    c.Netrc,
		Repo:     c.Repo,
		Stage:    c.Stage,
		System:   c.System,
		Environ:  c.Environ,
		Secret:   secret.StaticVars(c.Secrets),
	}
	spec := comp.Compile(nocontext)

	// create a step object for each pipeline step.
	for _, step := range spec.Steps {
		if step.RunPolicy == engine.RunNever {
			continue
		}
		c.Stage.Steps = append(c.Stage.Steps, &drone.Step{
			StageID:   c.Stage.ID,
			Number:    len(c.Stage.Steps) + 1,
			Name:      step.Name,
			Status:    drone.StatusPending,
			ErrIgnore: step.IgnoreErr,
		})
	}

	// configures the pipeline timeout.
	timeout := time.Duration(c.Repo.Timeout) * time.Minute
	ctx, cancel := context.WithTimeout(nocontext, timeout)
	defer cancel()

	// listen for operating system signals and cancel execution
	// when received.
	ctx = signal.WithContextFunc(ctx, func() {
		println("received signal, terminating process")
		cancel()
	})

	state := &pipeline.State{
		Build:  c.Build,
		Stage:  c.Stage,
		Repo:   c.Repo,
		System: c.System,
	}

	// enable debug logging
	logrus.SetLevel(logrus.WarnLevel)
	if c.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if c.Trace {
		logrus.SetLevel(logrus.TraceLevel)
	}
	logger.Default = logger.Logrus(
		logrus.NewEntry(
			logrus.StandardLogger(),
		),
	)

	engine, err := engine.New(&engine.EngineArgs{
		SSHPrivateKey: c.AWS.SSHPrivateKey,
		AWS: engine.EndpointArgs{
			Endpoint:        c.AWS.Endpoint,
			Region:          c.AWS.Region,
			AccessKeyID:     c.AWS.AccessKeyID,
			SecretAccessKey: c.AWS.SecretAccessKey,
		},
	})
	if err != nil {
		return err
	}

	err = runtime.NewExecer(
		pipeline.NopReporter(),
		console.New(c.Pretty),
		engine,
		c.Procs,
	).Exec(ctx, spec, state)

	if c.Dump {
		dump(state)
	}
	if err != nil {
		return err
	}
	switch state.Stage.Status {
	case drone.StatusError, drone.StatusFailing, drone.StatusKilled:
		os.Exit(1)
	}
	return nil
}

func dump(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func registerExec(app *kingpin.Application) {
	c := new(execCommand)
	c.Environ = map[string]string{}
	c.Secrets = map[string]string{}

	cmd := app.Command("exec", "executes a pipeline").
		Action(c.run)

	cmd.Arg("source", "source file location").
		Default(".drone.yml").
		FileVar(&c.Source)

	cmd.Flag("secrets", "secret parameters").
		StringMapVar(&c.Secrets)

	cmd.Flag("environ", "environment variables").
		StringMapVar(&c.Environ)

	cmd.Flag("debug", "enable debug logging").
		BoolVar(&c.Debug)

	cmd.Flag("trace", "enable trace logging").
		BoolVar(&c.Trace)

	cmd.Flag("dump", "dump the pipeline state to stdout").
		BoolVar(&c.Dump)

	cmd.Flag("pretty", "pretty print the output").
		Default(
			fmt.Sprint(
				isatty.IsTerminal(
					os.Stdout.Fd(),
				),
			),
		).BoolVar(&c.Pretty)

	cmd.Flag("private-key", "private key file path").
		ExistingFileVar(&c.AWS.SSHPrivateKey)

	cmd.Flag("aws-endpoint", "AWS endpoint").
		ExistingFileVar(&c.AWS.Endpoint)

	cmd.Flag("aws-access-key-id", "AWS access key").
		ExistingFileVar(&c.AWS.AccessKeyID)

	cmd.Flag("aws-secret-access-key", "AWS secret key").
		ExistingFileVar(&c.AWS.SecretAccessKey)

	cmd.Flag("aws-default-region", "AWS default region").
		ExistingFileVar(&c.AWS.Region)

	// shared pipeline flags
	c.Flags = internal.ParseFlags(cmd)
}
