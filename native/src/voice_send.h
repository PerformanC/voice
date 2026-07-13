#ifndef VOICE_SEND_H
#define VOICE_SEND_H

#include <stddef.h>
#include <stdint.h>

extern const uint8_t OPUS_SILENCE_FRAME[];
#define OPUS_SILENCE_FRAME_SIZE 3

#define VOICE_MAX_PACKET_SIZE 1232
#define RTP_HEADER_SIZE 12
#define TIMESTAMP_INCREMENT 960

enum voice_encryption_mode {
  VOICE_ENCRYPTION_AES256_GCM = 0,
  VOICE_ENCRYPTION_XCHACHA20  = 1
};

struct voice_send_stats {
  uint64_t packets_sent;
  uint64_t packets_lost;
  uint64_t packets_expected;
};

struct voice_send_ctx {
  enum voice_encryption_mode encryption;
  uint8_t secret_key[32];
  uint32_t ssrc;
  uint16_t sequence;
  uint32_t timestamp;
  uint32_t nonce;
  struct voice_send_stats stats;
};

struct voice_send_ctx *voice_send_init(struct voice_send_ctx *ctx,
                                       enum voice_encryption_mode encryption,
                                       const uint8_t secret_key[32],
                                       uint32_t ssrc,
                                       uint16_t initial_sequence,
                                       uint32_t initial_timestamp);

void voice_send_destroy(struct voice_send_ctx *ctx);

int voice_send_encrypt(struct voice_send_ctx *ctx,
                       const uint8_t *audio_chunk, size_t audio_len,
                       uint8_t *packet, size_t packet_capacity);

uint16_t voice_send_sequence(const struct voice_send_ctx *ctx);

uint32_t voice_send_timestamp(const struct voice_send_ctx *ctx);

uint32_t voice_send_nonce(const struct voice_send_ctx *ctx);

struct voice_send_stats voice_send_stats(const struct voice_send_ctx *ctx);

void voice_send_reset_nonce(struct voice_send_ctx *ctx, uint32_t nonce);

#endif /* VOICE_SEND_H */
