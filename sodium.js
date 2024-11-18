const libraries = {
  'sodium-native': (sodium) => ({
    crypto_aead_xchacha20poly1305_ietf_encrypt: (voice, packetBuffer, nonce, key) => {
      const buffer = Buffer.alloc(voice.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
      return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(buffer, null, voice, packetBuffer, nonce, key)
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt: (cipherVoice, packetBuffer, nonce, key) => {
      const buffer = Buffer.alloc(cipherVoice.length - sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES)
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(buffer, null, null, cipherVoice, packetBuffer, nonce, key)
    }
  }),
  'libsodium-wrappers': (sodium) => ({
    crypto_aead_xchacha20poly1305_ietf_encrypt: (voice, packetBuffer, nonce, key) => {
      return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(voice, packetBuffer, null, nonce, key)
    },
    crypto_aead_xchacha20poly1305_ietf_decrypt: (cipherVoice, packetBuffer, nonce, key) => {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipherVoice, packetBuffer, nonce, key)
    }
  })
}

const functions = {
  crypto_aead_xchacha20poly1305_ietf_encrypt: null,
  crypto_aead_xchacha20poly1305_ietf_decrypt: null,
}

void (async () => {
  let index = 0
  Object.keys(libraries).forEach(async (name) => {
    try {
      const lib = await import(name)

      if (functions.open) return;

      if (name == 'libsodium-wrappers') await lib.default.ready

      functions.crypto_aead_xchacha20poly1305_ietf_encrypt = libraries[name](lib.default).crypto_aead_xchacha20poly1305_ietf_encrypt
      functions.crypto_aead_xchacha20poly1305_ietf_decrypt = libraries[name](lib.default).crypto_aead_xchacha20poly1305_ietf_decrypt
    } catch {}

    if (index == 2 && !functions.open) {
      throw new Error('Could not load any sodium library')
    }

    index++
  })
})()

export default functions
