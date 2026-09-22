# go-sql-teradata

Pure Go Teradata driver for [`database/sql`](https://pkg.go.dev/database/sql).

I started creating this driver while working on another Go project and wanted to be able to connect to Teradata. The project is still in a very early phase and likely contains issues. If anyone out there is interested in using it and find any issues please let me know. 

## Install

```bash
go get github.com/atl3/go-sql-teradata
```

## Config Options

URL Param names *should* follow the official JDBC driver names and values. Reference the JDBC documentation for detail descriptions of the values. 

To date the connection options implemented are:

#### Base Options:
| Config Option | URL Param | Description | Allowed | Default |
|---------------|-----------| ------------|---------|---------|
| `Tmode` | `TMODE` | Transaction Mode | `DEFAULT`,`TERA`,`ANSI` | `DEFAULT` (Server Default) |
| `CopMode` | `COP` | Enable/Disable COP Discovery | `ON`,`OFF` | `ON` |
| `CopLast` | `COPLAST` | Performs DNS lookup of coplast to end COP discovery | `ON`,`OFF` | `ON` |
| `Timeout` | `TIMEOUT` | Connection Timeout in Seconds | >0 | `60` |
| `Partition` | `PARTITION` | |  | `DBC/SQL` |
| `ConnectFunction` | `CONNECT_FUNCTION` | | `0`,`1`,`2` | `0` |
| `MaxMessageSize` | `MAX_MESSAGE_BODY` | | >0 | `2097152` |
| `EncryptData` | `ENCRYPTDATA` | ON=Encrypt query data when not using TLS connection, OFF=Only encrypt authentication | `ON`,`OFF` | `OFF` |

#### TLS Options:
| Config Option | URL Param | Description | Allowed | Default |
|---------------|-----------| ------------|---------|---------|
| `SSLMode` | `SSLMODE` | TLS Connection Mode (see JDBC connection string reference) | `DISABLE`,`ALLOW`,`PREFER`,`REQUIRE`,`VERIFY-CA`,`VERIFY-FULL` | `PREFER` |
| `SSLProtocol` | `SSLPROTOCOL` | TLS Protocol Version for TLS Connections | | `TLSv1.3` |
| `SSLServerName` | `SSLSERVERNAME` | For TLS hostname verification | |  |
| `SSLCA` | `SSLCA` | Path to single PEM file |  |  |
| `SSLCAPath` | `SSLCAPATH` | Path to directory containing PEM files |  |  |
| `SSLBase64` | `SSLBASE64` | Base64 encoded contents of PEM file |  |  |
| `SSLPort` | `HTTPS_PORT` | Port to use for TLS connections |  | `443` |

#### LOB Options:
| Config Option | URL Param | Description | Allowed | Default |
|---------------|-----------| ------------|---------|---------|
| `LOBSupport` | `LOB_SUPPORT` | Enable/Disable LOB support | `ON`,`OFF` | `ON` |
| `LOBRecieveThreshold` | `SLOB_RECEIVE_THRESHOLD` | Threshold for inlining LOBs - use to tune memory usage | >0 | `1000` |
| `LOBPrefetch` | `LOB_PREFETCH` | Prefetch LOBs on rows.Next() - allows you to scan as string/[]byte directly but will have a negative memory impact for large LOBs | `ON`,`OFF` | `OFF` |

## TLS

By default the driver using SSLMode=Prefer and port 443. This means it will first attempt to connect with TLS on port 443 but won't enforce any certificate or hostname validations. Additionally it will fallback to the non-TLS port (1025 by default) if unable to establish a TLS connection.

- Setting SSLMode=REQUIRE will disable the fallback 
- Setting SSLMode=VERIFY-CA will additionally enforce certification validations using one or more of the SSLCA/Base64 params
- Setting SSLMode=VERIFY-FULL will additionally enforce hostname validations.

## LOB Support

LOB support is enabled by default. If its not-needed you can reduce some overhead by disabling it using LOBSupport=false config option.

By default LOBs won't be pre-fetched. Small LOBs will be inline from the server and available immediatly but large LOBs will require additional IO with the server to retreive. Example non-prefetched LOB usage (supressing err checks):


```go
import (
	"database/sql"
	"github.com/atl3/go-sql-teradata"
)

func main() {
    ...
    var (
        id int64
        clob teradata.TeradataClob
        blob teradata.TeradataBlob
    )
    for rows.Next() {
        err := rows.Scan(&id, &clob, &blob)
        clobVal, err := clob.GetString()
        blobVal, err := blob.GetBytes()
        ...
    }
    ...
}
```

If you are working with small LOBs and want to avoid using TeradataClob/TeradataBlob you can enable LOB Prefetch and read directly to string/byte:


```go

func main() {
    ...
    var (
        id int64
        clob sql.NullString
        blob []byte
    )
    for rows.Next() {
        err := rows.Scan(&id, &clob, &blob)
        ...
    }
    ...
}
```

...

## Logging

By default the driver won't log anything but you can enable trace logging as follows:

```go
import (
	"log/slog"
	"github.com/atl3/go-sql-teradata"
)

func main() {
    handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.Level(-8),
    })
    logger := slog.New(handler)

    cfg := &teradata.Config{
        ....,
        Logger: logger,
    }
    connector, err := teradata.NewConnector(cfg)
    ...
}
```

## Not Yet Implemented / TODOs
- XML Data Type
- Stored procedure support
- ARRAY / structured UDT data types 
- Query Banding
- FastLoad

----

__NOTE:__
```
Teradata is a registered trademark of Teradata Corporation. This project is an independent open-source driver and is not affiliated with, endorsed by, or sponsored by Teradata Corporation.
```