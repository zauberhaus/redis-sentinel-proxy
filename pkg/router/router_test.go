package router_test

import (
	"testing"

	"github.com/zauberhaus/redis-sentinel-proxy/pkg/router"
)

func TestGetDirection(t *testing.T) {
	tests := []struct {
		cmd  string
		want router.Direction
	}{
		// Core read commands
		{"GET", router.Read},
		{"MGET", router.Read},
		{"HGETALL", router.Read},
		{"LRANGE", router.Read},
		{"ZRANGE", router.Read},
		{"SCAN", router.Read},
		{"EXISTS", router.Read},
		{"XREAD", router.Read},
		{"PING", router.Read},
		{"INFO", router.Read},

		// Case-insensitive lookup
		{"get", router.Read},
		{"HGetAll", router.Read},

		// Core write commands
		{"SET", router.Write},
		{"DEL", router.Write},
		{"INCR", router.Write},
		{"HSET", router.Write},
		{"LPUSH", router.Write},
		{"ZADD", router.Write},
		{"XADD", router.Write},
		{"EXPIRE", router.Write},
		{"FLUSHALL", router.Write},

		// Commands with optional STORE / write side effects go to the master
		{"SORT", router.Write},
		{"GEORADIUS", router.Write},
		{"GETEX", router.Write},
		{"BITFIELD", router.Write},
		{"XREADGROUP", router.Write},
		{"EVAL", router.Write},
		{"PUBLISH", router.Write},
		{"MULTI", router.Write},

		// ...while their read-only variants stay on replicas
		{"SORT_RO", router.Read},
		{"GEORADIUS_RO", router.Read},
		{"BITFIELD_RO", router.Read},
		{"EVAL_RO", router.Read},

		// Module (extension) commands
		{"JSON.GET", router.Read},
		{"JSON.SET", router.Write},
		{"FT.SEARCH", router.Read},
		{"FT.CREATE", router.Write},
		{"BF.EXISTS", router.Read},
		{"BF.ADD", router.Write},
		{"CF.COUNT", router.Read},
		{"CMS.QUERY", router.Read},
		{"CMS.INCRBY", router.Write},
		{"TOPK.LIST", router.Read},
		{"TDIGEST.QUANTILE", router.Read},
		{"TDIGEST.ADD", router.Write},
		{"TS.RANGE", router.Read},
		{"TS.ADD", router.Write},
		{"GRAPH.RO_QUERY", router.Read},
		{"GRAPH.QUERY", router.Write},

		// Unknown commands default to the master
		{"SOMEFUTURECMD", router.Write},
		{"", router.Write},
	}

	for _, tt := range tests {
		if got := router.GetDirection(tt.cmd); got != tt.want {
			t.Errorf("GetDirection(%q) = %v, want %v", tt.cmd, got, tt.want)
		}
	}
}
