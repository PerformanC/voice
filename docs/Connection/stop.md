# stop

## Description

Stops the audio stream.

## Syntax

```
connection.stop('Player wanted to stop.')
```

> [!WARNING]  
> An error will be thrown if there is no audio stream to stop, or if the connection was not initialized. Always check if `connection.udp != null` before calling this function.

## Parameters

- `reason` - The reason that will be sent to `playerStateChange` listeners.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

### 1.0.4

- Added optional `reason` parameter

</details>
