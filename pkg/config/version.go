package config

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

type Version struct {
	BuildDate    time.Time `yaml:"BuildDate,omitempty"`
	Compiler     string    `yaml:"Compiler,omitempty"`
	GitCommit    string    `yaml:"GitCommit,omitempty"`
	GitTreeState string    `yaml:"GitTreeState,omitempty"`
	GitVersion   string    `yaml:"GitVersion,omitempty"`
	GoVersion    string    `yaml:"GoVersion,omitempty"`
	Platform     string    `yaml:"Platform,omitempty"`
	Executable   string    `yaml:"Executable,omitempty"`
}

func (v *Version) String() string {
	version := struct {
		Version *Version `yaml:"Version"`
	}{v}
	data, _ := yaml.Marshal(version)
	return string(data)
}

// NewVersion creates a new version object
func NewVersion(buildDate time.Time, gitCommit string, tag string, treeState string) *Version {
	var exec string
	if exePath, err := os.Executable(); err == nil {
		exec = exePath
	}

	return &Version{
		BuildDate:    buildDate,
		Compiler:     runtime.Compiler,
		GitCommit:    gitCommit,
		GitTreeState: treeState,
		GitVersion:   tag,
		GoVersion:    runtime.Version(),
		Platform:     fmt.Sprintf("%v/%v", runtime.GOOS, runtime.GOARCH),
		Executable:   exec,
	}
}
