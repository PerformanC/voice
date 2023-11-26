# unpause

## Description

Unpauses the audio stream.

## Syntax

```
connection.unpause()
```

> [!WARNING]  
> An error will be thrown if there is no audio stream to unpause, or if the connection was not initialized. Always check if `connection.udp != null` and `connection.ws != null` before calling this function.

## Return value

Nothing.

## Changelog
<details>

<summary>The changelog for this function can be found here.</summary>

### 1.0.0

- Initial implementation

</details>
