#include "voice_send.h"

#include <string.h>

#include <sodium.h>

#if defined(__GNUC__) || defined(__clang__)
  __attribute__((constructor))
#elif defined(_MSC_VER)
  #pragma section(".CRT$XCU", long, read)
#endif
static void auto_sodium_init(void) {
  if (sodium_init() < 0) {
    fprintf(stderr, "ERROR: libsodium initialization failed\n");
    abort();
  }
}

#ifdef _MSC_VER
  __declspec(allocate(".CRT$XCU")) static void (*auto_sodium_init_ptr)(void) = auto_sodium_init;
#endif

const uint8_t OPUS_SILENCE_FRAME[] = {
  0xF8, 0xFF, 0xFE
};

/* INFO: Write a 16-bit value in network (big-endian) order. */
static void wbe16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}

/* INFO: Write a 32-bit value in network (big-endian) order. */
static void wbe32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

struct voice_send_ctx *voice_send_init(struct voice_send_ctx *ctx,
                                       enum voice_encryption_mode encryption,
                                       const uint8_t secret_key[32],
                                       uint32_t ssrc,
                                       uint16_t initial_sequence,
                                       uint32_t initial_timestamp) {
  ctx->encryption = encryption;
  ctx->ssrc = ssrc;
  ctx->sequence = initial_sequence;
  ctx->timestamp = initial_timestamp;
  ctx->nonce = 0;

  memset(&ctx->stats, 0, sizeof(ctx->stats));
  memcpy(ctx->secret_key, secret_key, 32);

  return ctx;
}

void voice_send_destroy(struct voice_send_ctx *ctx) {
  sodium_memzero(ctx->secret_key, sizeof(ctx->secret_key));
}

/* INFO: Core encryption + packet building */
int voice_send_encrypt(struct voice_send_ctx *ctx,
                       const uint8_t *audio_chunk, size_t audio_len,
                       uint8_t *packet, size_t packet_capacity) {
  if (audio_chunk == NULL || audio_len == 0 || packet == NULL) return -1;
  if (packet_capacity < VOICE_MAX_PACKET_SIZE) return -1;

  /* INFO: RTP header (12 bytes) */
  packet[0] = 0x80; /* version 2 */
  packet[1] = 0x78; /* payload type 120 */
  wbe16(packet + 2, ctx->sequence);
  wbe32(packet + 4, ctx->timestamp);
  wbe32(packet + 8, ctx->ssrc);

  /* INFO: Nonce (24 bytes) */
  uint8_t nonce_buf[24] = { 0 };
  wbe32(nonce_buf, ctx->nonce);

  unsigned long long cipher_len = 0;
  /* INFO: Encrypt */
  switch (ctx->encryption) {
    case VOICE_ENCRYPTION_XCHACHA20: {
      if (crypto_aead_xchacha20poly1305_ietf_encrypt(packet + RTP_HEADER_SIZE, &cipher_len,
                                                     audio_chunk, audio_len,
                                                     packet, RTP_HEADER_SIZE,
                                                     NULL,
                                                     nonce_buf,
                                                     ctx->secret_key) < 0) {
        return -1;
      }

      break;
    }

    case VOICE_ENCRYPTION_AES256_GCM: {
      #ifdef crypto_aead_aes256gcm_NPUBBYTES
        if (!crypto_aead_aes256gcm_is_available())
          return -1;

        if (crypto_aead_aes256gcm_encrypt(packet + RTP_HEADER_SIZE, &cipher_len,
                                          audio_chunk, audio_len,
                                          packet, RTP_HEADER_SIZE,
                                          NULL,
                                          nonce_buf,
                                          ctx->secret_key) < 0) {
          return -1;
        }
      #else
        return -1;
      #endif

      break;
    }

    default: return -1;
  }

  /* INFO: Append 4-byte nonce at end */
  size_t off = RTP_HEADER_SIZE + (size_t)cipher_len;
  wbe32(packet + off, ctx->nonce);
  int ret = (int)(off + 4);

  /* INFO: Advance counters (after encryption, to preserve nonce = 0 on first) */
  ctx->sequence = (uint16_t)(ctx->sequence + 1);
  ctx->timestamp = (ctx->timestamp + TIMESTAMP_INCREMENT) & 0xFFFFFFFFu;
  ctx->nonce = (ctx->nonce + 1) & 0xFFFFFFFFu;

  ctx->stats.packets_expected++;

  return ret;
}

uint16_t voice_send_sequence(const struct voice_send_ctx *ctx) {
  return ctx->sequence;
}

uint32_t voice_send_timestamp(const struct voice_send_ctx *ctx) {
  return ctx->timestamp;
}

uint32_t voice_send_nonce(const struct voice_send_ctx *ctx) {
  return ctx->nonce;
}

struct voice_send_stats voice_send_stats(const struct voice_send_ctx *ctx) {
  return ctx->stats;
}

void voice_send_reset_nonce(struct voice_send_ctx *ctx, uint32_t nonce) {
  ctx->nonce = nonce;
}
