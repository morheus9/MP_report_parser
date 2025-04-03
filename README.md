# MaxPatrol Report Parser

#### Install dependencies
```
cd main
go mod tidy
```
#### build for windows
```
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" main.go
```
#### build for linux
```
CGO_ENABLED=0 go build -ldflags="-s -w"
```
#### Copy your zipped reports and start script
```
./main
```
