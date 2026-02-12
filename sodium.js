function u8ToBuf(u8) {
  return Buffer.isBuffer(u8)
    ? u8
    : Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength)
}

let api = null

// i did some benchmarks myself, and, sodium-native uses C++ bindings and is faster than libsodium-wrappers (WASM/JS)
// It also allows writing directly into pre-allocated buffers.
// https://sodium-friends.github.io/docs/docs/aead
// https://sodium-friends.github.io/docs/docs/aead#crypto_aead_xchacha20poly1305_ietf_decrypt
/* const ok = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    out,      // m: output buffer ('out')
    null,     // nsec: must be null
    cipher,   // c: ciphertext to decrypt
    aad,      // ad: additional data (optional, can be null)
    nonce,    // npub: nonce
    key       // k: key
) */
// now for the _into usage, this allows writing directly into pre-allocated buffers

try {
  const mod = await import('sodium-native')
  const sodium = mod.default ?? mod
  const ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

  api = {
    kind: 'sodium-native',
    ABYTES,
    crypto_aead_xchacha20poly1305_ietf_encrypt_into(out, msg, aad, nonce, key) {
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(out, null, msg, aad, nonce, key)
      return out
    },
    crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key) {
      const out = Buffer.allocUnsafe(msg.length + ABYTES)
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        out,
        null,
        msg,
        aad,
        nonce,
        key
      )
      return out
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt(cipher, aad, nonce, key) {
      const out = Buffer.allocUnsafe(cipher.length - ABYTES)
      const ok = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        out,
        null,
        cipher,
        aad,
        nonce,
        key
      )
      if (ok === false) throw new Error('sodium decrypt failed')
      return out
    }
  }
} catch {
  // ignore, it will fallback to libsodium-wrappers
}

if (!api) {
  const mod = await import('libsodium-wrappers')
  const sodium = mod.default ?? mod
  await sodium.ready
  const ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES

  api = {
    kind: 'libsodium-wrappers',
    ABYTES,
    crypto_aead_xchacha20poly1305_ietf_encrypt_into(out, msg, aad, nonce, key) {
      const enc = u8ToBuf(
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          msg,
          aad,
          null,
          nonce,
          key
        )
      )
      enc.copy(out)
      return out
    },
    crypto_aead_xchacha20poly1305_ietf_encrypt(msg, aad, nonce, key) {
      return u8ToBuf(
        sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          msg,
          aad,
          null,
          nonce,
          key
        )
      )
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt(cipher, aad, nonce, key) {
      return u8ToBuf(
        sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          cipher,
          aad,
          nonce,
          key
        )
      )
    }
  }
}

export default api