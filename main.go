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
	"shadelx-be-usermgmt/service/auth/repository"
	"shadelx-be-usermgmt/util"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	_ "github.com/lib/pq"
)

var db *sql.DB

const (
	dbhost = "localhost"
	dbport = "5432"
	dbuser = "sadhelx_usr"
	dbpass = "s4dhelx"
	dbname = "sdx_usermgmt_db"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8088"
	}

	var httpAddr = flag.String("http", ":"+port, "http listen address")
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stdout)
		logger = log.NewSyncLogger(logger)
		logger = log.With(logger,
			"service", "usermgmt",
			"time", log.DefaultTimestampUTC,
			"caller", log.DefaultCaller,
		)
	}
	level.Info(logger).Log("msg", "service started")
	defer level.Info(logger).Log("msg", "service ended")

	initDb()
	defer db.Close()

	configs := util.NewConfigurations(logger)

	// logger := log.NewLogfmtLogger(os.Stdout)

	flag.Parse()
	ctx := context.Background()

	var srv auth.Service
	{
		dbRepo := repository.NewPostgresRepository(
			db,
			logger,
		)
		authRepo := repository.NewAuthRepo(
			configs,
			logger,
		)
		repository := repository.NewRepo(
			*dbRepo,
			*authRepo,
			logger,
		)
		srv = auth.NewService(
			repository,
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
		level.Info(logger).Log("listening-on", port)
		handler := auth.NewHTTPServer(ctx, endpoints)
		errChan <- http.ListenAndServe(*httpAddr, handler)

	}()

	level.Error(logger).Log("exit", <-errChan)
	// transport.RegisterHttpsServicesAndStartListener()

	// logger.Log("listening-on", port)
	// if err := http.ListenAndServe(":"+port, nil); err != nil {
	// 	logger.Log("listen.error", err)
	// }
}

func initDb() {
	config := dbConfig()
	var err error
	psqlInfo := fmt.Sprintf("host=%s port=%s user=%s "+
		"password=%s dbname=%s sslmode=disable",
		config[dbhost], config[dbport],
		config[dbuser], config[dbpass], config[dbname])

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

func dbConfig() map[string]string {
	conf := make(map[string]string)

	//will use this later once we set the OS Environment

	/*host, ok := os.LookupEnv(dbhost)
	if !ok {
		panic("DBHOST environment variable required but not set")
	}
	port, ok := os.LookupEnv(dbport)
	if !ok {
		panic("DBPORT environment variable required but not set")
	}
	user, ok := os.LookupEnv(dbuser)
	if !ok {
		panic("DBUSER environment variable required but not set")
	}
	password, ok := os.LookupEnv(dbpass)
	if !ok {
		panic("DBPASS environment variable required but not set")
	}
	name, ok := os.LookupEnv(dbname)
	if !ok {
		panic("DBNAME environment variable required but not set")
	}*/
	conf[dbhost] = "localhost"
	conf[dbport] = "5432"
	conf[dbuser] = "sadhelx_usr"
	conf[dbpass] = "s4dhelx"
	conf[dbname] = "sdx_usermgmt_db"
	return conf
}
