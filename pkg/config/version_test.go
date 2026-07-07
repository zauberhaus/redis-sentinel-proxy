package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
)

func TestNewVersion(t *testing.T) {
	buildDate := time.Now()
	v := config.NewVersion(buildDate, "abc123", "v1.2.3", "clean")

	if !v.BuildDate.Equal(buildDate) {
		t.Errorf("BuildDate = %v, want %v", v.BuildDate, buildDate)
	}
	if v.GitCommit != "abc123" {
		t.Errorf("GitCommit = %q, want %q", v.GitCommit, "abc123")
	}
	if v.GitVersion != "v1.2.3" {
		t.Errorf("GitVersion = %q, want %q", v.GitVersion, "v1.2.3")
	}
	if v.GitTreeState != "clean" {
		t.Errorf("GitTreeState = %q, want %q", v.GitTreeState, "clean")
	}
	if v.Compiler == "" {
		t.Error("Compiler is empty")
	}
	if v.GoVersion == "" {
		t.Error("GoVersion is empty")
	}
	if !strings.Contains(v.Platform, "/") {
		t.Errorf("Platform = %q, want GOOS/GOARCH format", v.Platform)
	}
}

func TestVersionString(t *testing.T) {
	v := config.NewVersion(time.Time{}, "abc123", "v1.2.3", "clean")
	s := v.String()

	if !strings.Contains(s, "GitCommit: abc123") {
		t.Errorf("String() = %q, want it to contain GitCommit", s)
	}
	if !strings.Contains(s, "GitVersion: v1.2.3") {
		t.Errorf("String() = %q, want it to contain GitVersion", s)
	}
}
