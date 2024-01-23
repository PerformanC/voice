# udpSend 

## Description

Sends a UDP packet to the Discord voice server.

## Syntax

```
connection.udpSend(data, cb)
```

> [!WARNING]  
> An error will be thrown if the connection was not initialized. Always check if `connection.udp != null` before calling this function.

## Parameters

- `data` - The data to send.
- `cb` - The callback to call when the packet has been sent. The callback has the following parameters:
  - `error` - An `Error` if an error occurred, `null` otherwise.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

### 1.0.4

- Added optional `cb` parameter

</details>
