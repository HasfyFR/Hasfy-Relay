package main

import (
	"bufio"
	"os"
	"strings"
)

// loadEnvFile parses simple `KEY=VAL` lines (optionally prefixed by
// `export `) from the given file and applies any keys that are not yet
// set in the process environment. Quoted values are unquoted. Blank
// lines and `#` comments are ignored. Missing files are silently
// skipped — this is a best-effort loader for Vault Agent Injector
// templates that drop a single env file at /vault/secrets/env.
func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				v = v[1 : len(v)-1]
			}
		}
		if _, exists := os.LookupEnv(k); !exists {
			_ = os.Setenv(k, v)
		}
	}
}
