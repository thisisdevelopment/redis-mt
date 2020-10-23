# redis-mt

Status: POC

A redis proxy which provides multi-tenancy for redis. 
- each user can only see his own data 
- reverse dns is used to determine the username (kubernetes namespace name)
- all keys are automagically prefixed with "<user>:"
- users are automagically provisioned in the upstream redis server (uses redis 6 acl to restrict the keys to only the "<user>:" prefix)
- users are restricted to non-dangerous commands

## How to run

```
docker-compose up
```

```
cd src
go build main.go
cd ../
docker-compose exec app /src/main
```

```
docker-compose exec client1 keydb-cli -h app
```

```
docker-compose exec client2 keydb-cli -h app
```
