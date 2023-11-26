# sendAudioChunk 

## Description

Sends an audio chunk to the Discord voice server.

## Syntax

```
connection.sendAudioChunk(packetBuffer, data)
```

> [!WARNING]  
> An error will be thrown if the connection was not initialized. Always check if `connection.udp != null` before calling this function.

## Parameters

- `packetBuffer` - The packet buffer to use (12 bytes).
- `data` - The data to send.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

</details>
