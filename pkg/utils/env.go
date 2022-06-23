package utils

import (
	"log"
	"os"
	"strconv"
)

// MustGetEnv would get Env variable of die
func MustGetEnv(name string) string {
	value, found := os.LookupEnv(name)
	if !found {
		log.Fatalf("environment variable %s is missing", name)
	}
	return value
}

// MustGetEnvInt would get Env variable, make int from it of die
func MustGetEnvInt(name string) int {
	value, found := os.LookupEnv(name)
	if !found {
		log.Fatalf("environment variable %s is missing", name)
	}
	ret, err := strconv.Atoi(value)
	if err != nil {
		log.Fatalf("can't convert '%s' for name %s to int: %v", value, name, err)
	}
	return ret
}
