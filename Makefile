postgres:
	docker run --name sadhelx_db -p 5432:5432 -e POSTGRES_USER=sadhelx_usr -e POSTGRES_PASSWORD=s4dhelx -v sadhelx_postgres:/var/lib/postgresql/data -d postgres

createdb:
        docker exec -it sadhelx_db createdb --username=sadhelx_usr --owner=sadhelx_usr sdx_usermgmt_db

migrateup:
        cat db.sql | docker exec -i sadhelx_db pg_restore -U sadhelx_usr -d sdx_usermgmt_db

dropdb:
        docker exec -it sadhelx_db dropdb sdx_usermgmt_db

test:
        go test -v -cover ./...

server:
        go run main.go


.PHONY: postgres createdb dropdb test server 







