package common

import "log"

// FatalIfErr crashes the program with the given message when the error is not nil
func FatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}
