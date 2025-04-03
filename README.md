# MaxPatrol Report Parser

#### Install dependencies
```
cd main
go mod tidy
```
#### Build for windows
```
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w"
```
#### Build for linux
```
CGO_ENABLED=0 go build -ldflags="-s -w"
```
#### Copy your's zipped reports and start script
```
./main
```
