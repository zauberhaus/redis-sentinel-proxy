package router

import "strings"

type Direction int

const (
	Read Direction = iota
	Write
)

// readOnlyCommands contains all commands that never modify the dataset and
// can therefore be served by a replica. Every command not listed here is
// routed to the master (Write) — this is the safe default for write
// commands, admin/server commands, transactions, blocking commands and any
// unknown or future commands.
var readOnlyCommands = map[string]struct{}{
	// Connection
	"PING": {}, "ECHO": {}, "SELECT": {}, "AUTH": {}, "HELLO": {}, "QUIT": {},

	// Keyspace
	"EXISTS": {}, "TYPE": {}, "TTL": {}, "PTTL": {}, "EXPIRETIME": {}, "PEXPIRETIME": {},
	"KEYS": {}, "SCAN": {}, "RANDOMKEY": {}, "DUMP": {}, "TOUCH": {}, "OBJECT": {},
	"MEMORY": {},

	// Strings
	"GET": {}, "MGET": {}, "GETRANGE": {}, "SUBSTR": {}, "STRLEN": {}, "LCS": {},

	// Bitmaps
	"GETBIT": {}, "BITCOUNT": {}, "BITPOS": {}, "BITFIELD_RO": {},

	// Hashes
	"HGET": {}, "HMGET": {}, "HGETALL": {}, "HKEYS": {}, "HVALS": {}, "HLEN": {},
	"HEXISTS": {}, "HSTRLEN": {}, "HSCAN": {}, "HRANDFIELD": {},
	"HTTL": {}, "HPTTL": {}, "HEXPIRETIME": {}, "HPEXPIRETIME": {},

	// Lists
	"LRANGE": {}, "LLEN": {}, "LINDEX": {}, "LPOS": {},

	// Sets
	"SMEMBERS": {}, "SISMEMBER": {}, "SMISMEMBER": {}, "SCARD": {}, "SRANDMEMBER": {},
	"SSCAN": {}, "SINTER": {}, "SUNION": {}, "SDIFF": {}, "SINTERCARD": {},

	// Sorted sets
	"ZRANGE": {}, "ZRANGEBYSCORE": {}, "ZRANGEBYLEX": {}, "ZREVRANGE": {},
	"ZREVRANGEBYSCORE": {}, "ZREVRANGEBYLEX": {}, "ZCARD": {}, "ZCOUNT": {},
	"ZLEXCOUNT": {}, "ZSCORE": {}, "ZMSCORE": {}, "ZRANK": {}, "ZREVRANK": {},
	"ZSCAN": {}, "ZRANDMEMBER": {}, "ZDIFF": {}, "ZINTER": {}, "ZUNION": {},
	"ZINTERCARD": {},

	// HyperLogLog
	"PFCOUNT": {},

	// Geo (the plain GEORADIUS/GEORADIUSBYMEMBER can STORE, so only the
	// read-only variants and pure queries are listed)
	"GEOPOS": {}, "GEODIST": {}, "GEOHASH": {}, "GEOSEARCH": {},
	"GEORADIUS_RO": {}, "GEORADIUSBYMEMBER_RO": {},

	// Streams (XREADGROUP mutates consumer-group state and is not listed)
	"XRANGE": {}, "XREVRANGE": {}, "XLEN": {}, "XREAD": {}, "XINFO": {}, "XPENDING": {},

	// Sort (plain SORT can STORE, only the read-only variant is listed)
	"SORT_RO": {},

	// Scripting (plain EVAL/EVALSHA/FCALL may write and are not listed)
	"EVAL_RO": {}, "EVALSHA_RO": {}, "FCALL_RO": {},

	// Pub/Sub (PUBLISH/SPUBLISH must go to the master and are not listed)
	"SUBSCRIBE": {}, "UNSUBSCRIBE": {}, "PSUBSCRIBE": {}, "PUNSUBSCRIBE": {},
	"SSUBSCRIBE": {}, "SUNSUBSCRIBE": {}, "PUBSUB": {},

	// Server introspection
	"INFO": {}, "TIME": {}, "DBSIZE": {}, "COMMAND": {}, "LASTSAVE": {}, "LOLWUT": {},

	// RedisJSON
	"JSON.GET": {}, "JSON.MGET": {}, "JSON.TYPE": {}, "JSON.STRLEN": {},
	"JSON.ARRLEN": {}, "JSON.ARRINDEX": {}, "JSON.OBJKEYS": {}, "JSON.OBJLEN": {},
	"JSON.DEBUG": {}, "JSON.RESP": {},

	// RediSearch (FT.CURSOR is stateful per node and is not listed)
	"FT.SEARCH": {}, "FT.AGGREGATE": {}, "FT.EXPLAIN": {}, "FT.EXPLAINCLI": {},
	"FT.INFO": {}, "FT.PROFILE": {}, "FT.TAGVALS": {}, "FT.SPELLCHECK": {},
	"FT.SUGGET": {}, "FT.SUGLEN": {}, "FT.DICTDUMP": {}, "FT.SYNDUMP": {},
	"FT._LIST": {},

	// RedisBloom — Bloom filter
	"BF.EXISTS": {}, "BF.MEXISTS": {}, "BF.INFO": {}, "BF.CARD": {}, "BF.SCANDUMP": {},

	// RedisBloom — Cuckoo filter
	"CF.EXISTS": {}, "CF.MEXISTS": {}, "CF.COUNT": {}, "CF.INFO": {}, "CF.SCANDUMP": {},

	// RedisBloom — Count-min sketch
	"CMS.QUERY": {}, "CMS.INFO": {},

	// RedisBloom — Top-K
	"TOPK.QUERY": {}, "TOPK.COUNT": {}, "TOPK.LIST": {}, "TOPK.INFO": {},

	// RedisBloom — t-digest
	"TDIGEST.QUANTILE": {}, "TDIGEST.CDF": {}, "TDIGEST.MIN": {}, "TDIGEST.MAX": {},
	"TDIGEST.RANK": {}, "TDIGEST.REVRANK": {}, "TDIGEST.BYRANK": {},
	"TDIGEST.BYREVRANK": {}, "TDIGEST.TRIMMED_MEAN": {}, "TDIGEST.INFO": {},

	// RedisTimeSeries
	"TS.GET": {}, "TS.MGET": {}, "TS.RANGE": {}, "TS.REVRANGE": {},
	"TS.MRANGE": {}, "TS.MREVRANGE": {}, "TS.INFO": {}, "TS.QUERYINDEX": {},

	// RedisGraph
	"GRAPH.RO_QUERY": {}, "GRAPH.EXPLAIN": {}, "GRAPH.LIST": {}, "GRAPH.SLOWLOG": {},
}

// GetDirection returns whether cmd can be served by a replica (Read) or must
// be routed to the master (Write). Unknown commands are treated as Write.
func GetDirection(cmd string) Direction {
	if _, ok := readOnlyCommands[strings.ToUpper(cmd)]; ok {
		return Read
	}
	return Write
}
