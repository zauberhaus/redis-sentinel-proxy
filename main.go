// cspell:words TLSCA errgroup
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/config"
	masterresolver "github.com/zauberhaus/redis-sentinel-proxy/pkg/master_resolver"
	"github.com/zauberhaus/redis-sentinel-proxy/pkg/proxy"
	"golang.org/x/sync/errgroup"
)

const (
	ISO8601 = "2006-01-02T15:04:05Z0700"
)

var (
	bt        time.Time
	tag       string // git tag used to build the program
	gitCommit string // sha1 revision used to build the program
	buildTime string // when the executable was built
	treeState string // git tree state
)

func main() {
	var err error

	if tag == "" {
		tag = "dev"
		treeState = "dirty"
	}

	if buildTime != "" {
		bt, err = time.Parse(ISO8601, buildTime)
		if err != nil {
			panic(err)
		}
	}

	t := reflect.TypeOf(config.Version{})
	name := strings.Split(t.PkgPath(), "/")
	exec := name[len(name)-3]

	version := config.NewVersion(bt, gitCommit, tag, treeState)

	configFile := flag.String("config", "", "path to a YAML config file (explicit CLI flags take precedence over its values)")
	fromFlags := config.BindFlags(flag.CommandLine)
	flag.Parse()

	cfg, err := config.Load(fromFlags(), *configFile)
	if err != nil {
		log.Fatalf("Fatal: %s", err)
	}

	log.Printf("Start %v\n%v\n%v", exec, version, cfg)

	if err := runProxying(cfg); err != nil {
		log.Fatalf("Fatal: %s", err)
	}
	log.Println("Exiting...")
}

func runProxying(cfg *config.Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	masterAddrResolver := masterresolver.NewRedisMasterResolver(cfg)
	rsp, err := proxy.NewRedisSentinelProxy(cfg, masterAddrResolver)
	if err != nil {
		return err
	}

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error { return masterAddrResolver.UpdateMasterAddressLoop(ctx) })
	eg.Go(func() error { return rsp.Run(ctx) })
	return eg.Wait()
}
