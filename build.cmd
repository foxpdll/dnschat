set GODEBUG="rsa1024min=0"
rem set GOARCH=amd64
rem set GOOS=linux
del dnschat.exe
go build -ldflags="-extldflags=-static"
