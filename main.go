package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jclegras/tinyca/common"

	"github.com/gorilla/mux"
	"github.com/jclegras/tinyca/router"
)

func main() {
	log := common.GetLogger()
	r := mux.NewRouter()

	r.HandleFunc("/sign", router.SignHandler).Methods("POST")
	r.HandleFunc("/signCSR", router.SignCsrHandler).Methods("POST")

	port, portOverriden := os.LookupEnv("PORT")
	if !portOverriden {
		port = "8080"
	}
	log.Printf("Listening on port %s", port)

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("0.0.0.0:%s", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	var wait time.Duration
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	srv.Shutdown(ctx)
	log.Println("shutting down")

	os.Exit(0)
}
