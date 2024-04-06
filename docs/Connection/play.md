# play 

## Description

Plays an audio stream.

## Syntax

```
connection.play(stream)
```

> [!WARNING]  
> The connection must be initialized before calling this function. Always check if `connection.udp != null` before calling this function. Make sure that the stream is an Opus stream.

> [!IMPORTANT]
> The stream real ending MUST end with 0 (as Buffer), otherwise it will persist with the interval to play packets.

## Parameters

- `stream` - The stream to play.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

### 2.0.0

- Requires the stream to end with 0 (as Buffer) to stop playing.

</details>
