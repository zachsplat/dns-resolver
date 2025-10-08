# dns-resolver

recursive DNS resolver in Go. builds and sends DNS queries from scratch,
no net.Resolver or any of that. handles A, AAAA, CNAME, NS records.

mostly educational but it actually works for basic lookups.

## build

```
go build -o resolve ./cmd/resolve
```

## usage

```
./resolve example.com
./resolve -type AAAA example.com
./resolve -trace example.com   # show full recursion
```

## known issues

- no TCP fallback for large responses
- cache doesn't respect individual record TTLs, just uses the first one
- probably breaks on weird EDNS stuff
