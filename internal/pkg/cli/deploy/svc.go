// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the structures to deploy a workload.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws/session"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"

	awscloudformation "github.com/aws/copilot-cli/internal/pkg/aws/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/config"
	"github.com/aws/copilot-cli/internal/pkg/deploy"
	"github.com/aws/copilot-cli/internal/pkg/deploy/cloudformation"
	"github.com/aws/copilot-cli/internal/pkg/term/color"
	"github.com/aws/copilot-cli/internal/pkg/term/log"
)

type uploader interface {
	Upload(bucket, key string, data io.Reader) (string, error)
}

type versionGetter interface {
	Version() (string, error)
}

type serviceForceUpdater interface {
	ForceUpdateService(app, env, svc string) error
	LastUpdatedAt(app, env, svc string) (time.Time, error)
}

type aliasCertValidator interface {
	ValidateCertAliases(aliases []string, certs []string) error
}

type svcDeployer struct {
	*workloadDeployer
	newSvcUpdater func(func(*session.Session) serviceForceUpdater) serviceForceUpdater
	now           func() time.Time
}

func newSvcDeployer(in *WorkloadDeployerInput) (*svcDeployer, error) {
	wkldDeployer, err := newWorkloadDeployer(in)
	if err != nil {
		return nil, err
	}
	return &svcDeployer{
		workloadDeployer: wkldDeployer,
		newSvcUpdater: func(f func(*session.Session) serviceForceUpdater) serviceForceUpdater {
			return f(wkldDeployer.envSess)
		},
		now: time.Now,
	}, nil
}

func (d *svcDeployer) deploy(deployOptions Options, stackConfigOutput svcStackConfigurationOutput) (bool, bool, error) {
	opts := []awscloudformation.StackOption{
		awscloudformation.WithRoleARN(d.env.ExecutionRoleARN),
	}
	if deployOptions.DisableRollback {
		opts = append(opts, awscloudformation.WithDisableRollback())
	}
	cmdRunAt := d.now()
	eg, ctx := errgroup.WithContext(context.Background())
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGINT)
	var isSvcDeleted, isUpdateCanceled bool
	eg.Go(func() error {
		for {
			select {
			case <-signalCh:
				cancel()
				signal.Stop(signalCh)
				close(signalCh)
				isCreateInProgress, err := d.deployer.IsStackCreateInProgress(stackConfigOutput.conf.StackName())
				if err != nil {
					return err
				}
				if isCreateInProgress {
					isSvcDeleted = true
					log.Infof(color.Red.Sprintf("Received Interrupt for Ctrl-C.\nPressing Ctrl-C again will exit immediately but the deletion of stack %s still happens\n", stackConfigOutput.conf.StackName()))
					return d.deployer.DeleteWorkload(deploy.DeleteWorkloadInput{
						Name:             d.name,
						AppName:          d.app.Name,
						EnvName:          d.env.Name,
						ExecutionRoleARN: d.env.ExecutionRoleARN,
					})
				}
				isUpdateInProgress, err := d.deployer.IsStackUpdateInProgress(stackConfigOutput.conf.StackName())
				if err != nil {
					return err
				}
				if isUpdateInProgress {
					isUpdateCanceled = true
					log.Infof(color.Red.Sprintf("Received Interrupt for Ctrl-C.\nPressing Ctrl-C again will exit immediately but note that the stack %s rollback will continue unaffected\n", stackConfigOutput.conf.StackName()))
					return d.deployer.CancelUpdateWorkload(stackConfigOutput.conf.StackName())
				}
				return nil
			case <-ctx.Done():
				return nil
			}
		}
	})
	eg.Go(func() error {
		defer cancel()
		if err := d.deployer.DeployService(ctx, stackConfigOutput.conf, d.resources.S3Bucket, opts...); err != nil {
			var errEmptyCS *awscloudformation.ErrChangeSetEmpty
			if errors.Is(err, context.Canceled) {
				return nil
			}
			if !errors.As(err, &errEmptyCS) {
				return fmt.Errorf("deploy service: %w", err)
			}
			if !deployOptions.ForceNewUpdate {
				log.Warningln("Set --force to force an update for the service.")
				return fmt.Errorf("deploy service: %w", err)
			}
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return isSvcDeleted, isUpdateCanceled, err
	}
	// Force update the service if --force is set and the service is not updated by the CFN.
	if deployOptions.ForceNewUpdate {
		lastUpdatedAt, err := stackConfigOutput.svcUpdater.LastUpdatedAt(d.app.Name, d.env.Name, d.name)
		if err != nil {
			return isSvcDeleted, isUpdateCanceled, fmt.Errorf("get the last updated deployment time for %s: %w", d.name, err)
		}
		if cmdRunAt.After(lastUpdatedAt) {
			if err := d.forceDeploy(&forceDeployInput{
				spinner:    d.spinner,
				svcUpdater: stackConfigOutput.svcUpdater,
			}); err != nil {
				return isSvcDeleted, isUpdateCanceled, err
			}
		}
	}
	return isSvcDeleted, isUpdateCanceled, nil
}

type svcStackConfigurationOutput struct {
	conf       cloudformation.StackConfiguration
	svcUpdater serviceForceUpdater
}

type errAppOutOfDate struct {
	svc           string
	curVersion    string
	neededVersion string
}

func (e *errAppOutOfDate) Error() string {
	return fmt.Sprintf("app version must be >= %s", e.neededVersion)
}

func (e *errAppOutOfDate) RecommendActions() string {
	return fmt.Sprintf(`Cannot deploy service %q because the current application version %q
is incompatible. To upgrade the application, please run %s.
(see https://aws.github.io/copilot-cli/docs/credentials/#application-credentials)
`, e.svc, e.curVersion, color.HighlightCode("copilot app upgrade"))
}

func validateMinAppVersion(app, svc string, appVersionGetter versionGetter, minVersion string) error {
	appVersion, err := appVersionGetter.Version()
	if err != nil {
		return fmt.Errorf("get version for app %q: %w", app, err)
	}

	diff := semver.Compare(appVersion, minVersion)
	if diff < 0 {
		return &errAppOutOfDate{
			svc:           svc,
			curVersion:    appVersion,
			neededVersion: minVersion,
		}
	}

	return nil
}

func validateAliases(app *config.Application, env string, aliases ...string) error {
	// Alias should be within either env, app, or root hosted zone.
	regRoot, err := regexp.Compile(fmt.Sprintf(`^([^\.]+\.)?%s`, app.Domain))
	if err != nil {
		return err
	}
	regApp, err := regexp.Compile(fmt.Sprintf(`^([^\.]+\.)?%s.%s`, app.Name, app.Domain))
	if err != nil {
		return err
	}
	regEnv, err := regexp.Compile(fmt.Sprintf(`^([^\.]+\.)?%s.%s.%s`, env, app.Name, app.Domain))
	if err != nil {
		return err
	}

	regexps := []*regexp.Regexp{regRoot, regApp, regEnv}
	validate := func(alias string) error {
		for _, reg := range regexps {
			if reg.MatchString(alias) {
				return nil
			}
		}

		return &errInvalidAlias{
			alias: alias,
			app:   app,
			env:   env,
		}
	}

	for _, alias := range aliases {
		if err := validate(alias); err != nil {
			return err
		}
	}

	return nil
}

type errInvalidAlias struct {
	alias string
	app   *config.Application
	env   string
}

func (e *errInvalidAlias) Error() string {
	return fmt.Sprintf("alias %q is not supported in hosted zones managed by Copilot", e.alias)
}

func (e *errInvalidAlias) RecommmendActions() string {
	return fmt.Sprintf(`Copilot-managed aliases must match one of the following patterns:
- <name>.%s.%s.%s
- %s.%s.%s
- <name>.%s.%s
- %s.%s
- <name>.%s
- %s
`, e.env, e.app.Name, e.app.Domain,
		e.env, e.app.Name, e.app.Domain,
		e.app.Name, e.app.Domain,
		e.app.Name, e.app.Domain,
		e.app.Domain,
		e.app.Domain)
}
