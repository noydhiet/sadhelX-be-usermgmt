package main

import (
	"context"
	"database/sql"
	_ "expvar"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"shadelx-be-usermgmt/service/auth"
	"shadelx-be-usermgmt/service/auth/pkg/mailer"
	"shadelx-be-usermgmt/service/auth/repository"
	"shadelx-be-usermgmt/util"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	_ "github.com/lib/pq"
)

var db *sql.DB

func main() {

	// Logfmt is a structured, key=val logging format that is easy to read and parse
	// Direct any attempts to use Go's log package to our structured logger
	// stdlog.SetOutput(log.NewStdlibAdapter(logger))

	// Create an instance of our LoggingMiddleware with our configured logger
	// loggedRouter := loggingMiddleware(router)

	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stdout)
		logger = log.NewSyncLogger(logger)
		// Log the timestamp (in UTC) and the callsite (file + line number) of the logging
		// call for debugging in the future.
		logger = log.With(logger,
			"service", "usermgmt",
			"time", log.DefaultTimestampUTC,
			"caller", log.DefaultCaller,
		)
	}
	loggingMiddleware := auth.LoggingMiddleware(logger)

	level.Info(logger).Log("msg", "service started")
	defer level.Info(logger).Log("msg", "service ended")

	configs := util.NewConfigurations(logger)
	initDb(configs)
	defer db.Close()

	var httpAddr = flag.String("http", ":"+configs.ServerPort, "http listen address")

	flag.Parse()
	ctx := context.Background()

	var srv auth.Service
	{
		svcRepository := repository.NewRepo(db, logger)
		svcMailer := mailer.NewSGMailService(configs)

		srv = auth.NewService(
			svcMailer,
			svcRepository,
			configs,
			logger,
		)
	}
	endpoints := auth.MakeAuthEndpoints(srv)

	errChan := make(chan error)

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errChan <- fmt.Errorf("%s", <-c)
	}()

	go func() {
		level.Info(logger).Log("listening-on", configs.ServerPort)
		handler := auth.NewHTTPServer(ctx, endpoints)
		errChan <- http.ListenAndServe(*httpAddr, loggingMiddleware(handler))

	}()

	level.Error(logger).Log("exit", <-errChan)

}

func initDb(confs *util.Configurations) {
	// config := dbConfig()
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		confs.DBHost, confs.DBPort,
		confs.DBUser, confs.DBPass, confs.DBName)

	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	}
	fmt.Println("Successfully connected!")

}
