# unpause

## Description

Unpauses the audio stream.

## Syntax

```
connection.unpause('Player wanted to resume.')
```

> [!WARNING]  
> An error will be thrown if there is no audio stream to unpause, or if the connection was not initialized. Always check if `connection.udp != null` and `connection.ws != null` before calling this function.

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
