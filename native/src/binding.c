#include <string.h>

#include <node_api.h>
#include <sodium.h>

#include "os_compat.h"
#include "cthreads.h"
#include "voice_send.h"
#include "utils.h"

#define OPUS_FRAME_DURATION 20

#define AUDIO_QUEUE_SIZE 48 /* INFO: ~1 second of audio at 20ms frames */
#define AUDIO_QUEUE_LOW 16  /* INFO: resume when below this */

struct audio_queue {
  uint8_t data[AUDIO_QUEUE_SIZE][VOICE_MAX_PACKET_SIZE];
  size_t len[AUDIO_QUEUE_SIZE];
  unsigned head;    /* INFO: read index (loop consumes from here) */
  unsigned tail;    /* INFO: write index (JS pushes to here) */
  unsigned count;
  unsigned dropped;
};

struct native_ctx {
  struct voice_send_ctx ctx;

  /* INFO: Audio queue and synchronisation */
  struct cthreads_mutex audio_mutex;
  struct cthreads_cond  audio_cond;
  struct audio_queue audio_q;

  struct cthreads_thread loop_thread;
  volatile int loop_running;
  volatile int loop_eos; /* INFO: Enf-Of-Stream flag */
  os_socket_t udp_fd;
  struct sockaddr_in udp_addr;

  napi_threadsafe_function stats_tsfn;
  int stats_counter;
};


/* INFO: Thread: audio send loop */
static void *loop_thread_func(void *arg) {
  struct native_ctx *nc = (struct native_ctx *)arg;

  uint8_t audio[VOICE_MAX_PACKET_SIZE];
  uint8_t packet[VOICE_MAX_PACKET_SIZE];
  long long next_send = os_now_ns();

  while (nc->loop_running) {
    size_t alen = 0;
    int should_resume = 0;

    cthreads_mutex_lock(&nc->audio_mutex);

    /* INFO: Wait for audio data, or until it's time for the next packet */
    while (nc->audio_q.count == 0 && !nc->loop_eos && nc->loop_running) {
      long long remaining = next_send - os_now_ns();
      if (remaining <= 0) break; /* time to send (silence or late) */

      int wait_ms = (int)(remaining / 1000000LL);
      if (wait_ms < 1) wait_ms = 1;

      /* If next_send is more than one frame ahead, the audio send burst
           pushed it forward — reset to now and send immediately */
      if (wait_ms > OPUS_FRAME_DURATION) {
        next_send = os_now_ns();

        break;
      }

      int ret = cthreads_cond_timedwait(&nc->audio_cond, &nc->audio_mutex, wait_ms);
      if (ret != 0) break; /* timeout or error */
    }

    if (!nc->loop_running) {
      cthreads_mutex_unlock(&nc->audio_mutex);

      break;
    }

    if (nc->audio_q.count > 0) {
      unsigned prev_count = nc->audio_q.count;
      memcpy(audio, nc->audio_q.data[nc->audio_q.head], nc->audio_q.len[nc->audio_q.head]);
      alen = nc->audio_q.len[nc->audio_q.head];
      nc->audio_q.head = (nc->audio_q.head + 1) % AUDIO_QUEUE_SIZE;
      nc->audio_q.count--;

      /* INFO: If we drained below low water mark, signal main thread to resume stream */
      if (prev_count > AUDIO_QUEUE_LOW && nc->audio_q.count <= AUDIO_QUEUE_LOW)
        should_resume = 1;

      cthreads_cond_signal(&nc->audio_cond);
    }

    cthreads_mutex_unlock(&nc->audio_mutex);

    if (should_resume && nc->stats_tsfn != NULL)
      napi_call_threadsafe_function(nc->stats_tsfn, NULL, napi_tsfn_nonblocking);

    if (nc->loop_eos && nc->audio_q.count == 0 && alen == 0)
      break;

    /* INFO: Encrypt */
    int pkt_len;
    if (alen > 0)
      pkt_len = voice_send_encrypt(&nc->ctx, audio, alen, packet, sizeof(packet));
    else
      pkt_len = voice_send_encrypt(&nc->ctx, OPUS_SILENCE_FRAME, OPUS_SILENCE_FRAME_SIZE, packet, sizeof(packet));

    /* INFO: Send via UDP */
    if (pkt_len > 0) {
      int sent = os_sendto(nc->udp_fd, packet, (size_t)pkt_len, 0, (const struct sockaddr *)&nc->udp_addr, sizeof(nc->udp_addr));
      if (sent == (ssize_t)pkt_len) {
        nc->ctx.stats.packets_sent++;

        /* INFO: Update the stats counter and sync to JS every 50 packets */
        nc->stats_counter++;
        if (nc->stats_tsfn != NULL && nc->stats_counter >= 50) {
          nc->stats_counter = 0;
          napi_call_threadsafe_function(nc->stats_tsfn, NULL, napi_tsfn_nonblocking);
        }
      } else {
        nc->ctx.stats.packets_lost++;
      }
    } else {
      nc->ctx.stats.packets_lost++;
    }

    /* INFO: Schedule next packet exactly 20ms after this one */
    next_send += (long long)OPUS_FRAME_DURATION * 1000000LL;
  }

  nc->loop_running = 0;

  return NULL;
}

static int init_loop_fields(struct native_ctx *nc) {
  int ret = cthreads_mutex_init(&nc->audio_mutex, NULL);
  if (ret != 0) return -1;

  ret = cthreads_cond_init(&nc->audio_cond, NULL);
  if (ret != 0) {
    cthreads_mutex_destroy(&nc->audio_mutex);

    return -1;
  }

  return 0;
}

static void destroy_loop_fields(struct native_ctx *nc) {
  cthreads_mutex_destroy(&nc->audio_mutex);
  cthreads_cond_destroy(&nc->audio_cond);
}

/* INFO: Safely stop the audio loop and wait for it to finish */
static void stop_loop_and_join(struct native_ctx *nc) {
  if (!nc->loop_running) return;

  nc->loop_running = 0;
  cthreads_mutex_lock(&nc->audio_mutex);
  cthreads_cond_signal(&nc->audio_cond);
  cthreads_mutex_unlock(&nc->audio_mutex);
  cthreads_thread_join(nc->loop_thread, NULL);
}

/* INFO: Finalizer called when the JS wrapper is GC'd */
static void finalize_native_ctx(napi_env env, void *data, void *hint) {
  (void)env; (void)hint;

  struct native_ctx *nc = (struct native_ctx *)data;

  if (nc != NULL) {
    stop_loop_and_join(nc);

    if (nc->stats_tsfn != NULL) {
      napi_release_threadsafe_function(nc->stats_tsfn, napi_tsfn_abort);
      nc->stats_tsfn = NULL;
    }

    destroy_loop_fields(nc);
    voice_send_destroy(&nc->ctx);
    free(nc);
  }
}

static napi_status unwrap_ctx(napi_env env, napi_value val, struct native_ctx **out) {
  return napi_unwrap(env, val, (void **)out);
}

/* INFO: createContext(encryption, key, ssrc, seq, ts) */
static napi_value create_context(napi_env env, napi_callback_info info) {
  NAPI_GET_CB_INFO(5)

  int encryption;
  NAPI_GET_VALUE(encryption, 0, int32)

  void *key_data;
  size_t key_len;
  status = napi_get_buffer_info(env, args[1], &key_data, &key_len);
  if (status != napi_ok || key_len < 32) {
    napi_throw_type_error(env, NULL, "key must be a Buffer of at least 32 bytes");

    return NULL;
  }

  uint32_t ssrc;
  NAPI_GET_VALUE(ssrc, 2, uint32)

  uint32_t seq;
  NAPI_GET_VALUE(seq, 3, uint32)

  uint32_t ts;
  NAPI_GET_VALUE(ts, 4, uint32)

  struct native_ctx *nc = (struct native_ctx *)calloc(1, sizeof(struct native_ctx));
  if (nc == NULL) {
    napi_throw_error(env, NULL, "Out of memory");

    return NULL;
  }

  if (init_loop_fields(nc) != 0) {
    napi_throw_error(env, NULL, "Failed to initialise synchronisation primitives");

    goto cleanup_nc_fail;
  }

  if (voice_send_init(&nc->ctx, (enum voice_encryption_mode)encryption, (const uint8_t *)key_data, ssrc, (uint16_t)(seq & 0xFFFF), ts) == NULL) {
    napi_throw_error(env, NULL, "voice_send_init failed");

    goto cleanup_fields_fail;
  }

  napi_value result;
  status = napi_create_object(env, &result);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "napi_create_object failed");

    goto cleanup_all_fail;
  }

  status = napi_wrap(env, result, (void *)nc, finalize_native_ctx, NULL, NULL);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "napi_wrap failed");

    goto cleanup_all_fail;
  }

  return result;

  cleanup_all_fail:
    voice_send_destroy(&nc->ctx);
  cleanup_fields_fail:
    destroy_loop_fields(nc);
  cleanup_nc_fail:
    free(nc);

    return NULL;
}

/* INFO: startSendLoop(ctx, fd, ip, port) */
static napi_value start_send_loop(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(4)

  if (nc->loop_running) {
    napi_throw_error(env, NULL, "Loop is already running");

    return NULL;
  }

  int32_t fd;
  NAPI_GET_VALUE_EXTRA(fd, 1, int32, fd >= 0, "a valid file descriptor")

  char ip_str[64];
  size_t ip_len;
  status = napi_get_value_string_utf8(env, args[2], ip_str, sizeof(ip_str), &ip_len);
  if (status != napi_ok || ip_len == 0) {
    napi_throw_type_error(env, NULL, "ip must be a string");

    return NULL;
  }

  int32_t port;
  NAPI_GET_VALUE_EXTRA(port, 3, int32, port > 0 && port <= 65535, "a valid port number")

  nc->udp_fd = (os_socket_t)fd;
  memset(&nc->udp_addr, 0, sizeof(nc->udp_addr));
  nc->udp_addr.sin_family = AF_INET;
  nc->udp_addr.sin_port = htons((uint16_t)port);
  if (os_inet_pton(ip_str, &nc->udp_addr.sin_addr) <= 0) {
    napi_throw_type_error(env, NULL, "Invalid IP address");

    return NULL;
  }

  nc->loop_running = 1;
  {
    struct cthreads_args thr_args;
    thr_args.func = loop_thread_func;
    thr_args.data = nc;
    if (cthreads_thread_create(&nc->loop_thread, NULL, loop_thread_func, nc, &thr_args) != 0) {
      napi_throw_error(env, NULL, "Failed to create loop thread");

      nc->loop_running = 0;

      return NULL;
    }
  }

  napi_get_undefined(env, &args[0]);

  return args[0];
}

/* INFO: pushAudio(ctx, chunk) */
static napi_value push_audio(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(2)

  /* INFO: Handle both Buffer (non-empty) and null (end-of-stream) */
  napi_valuetype t;
  napi_typeof(env, args[1], &t);
  if (t == napi_null || t == napi_undefined) {
    cthreads_mutex_lock(&nc->audio_mutex);

    nc->loop_eos = 1;
    cthreads_cond_signal(&nc->audio_cond);

    cthreads_mutex_unlock(&nc->audio_mutex);

    napi_get_undefined(env, &args[0]);

    return args[0];
  }

  void *chunk_data;
  size_t chunk_len;
  status = napi_get_buffer_info(env, args[1], &chunk_data, &chunk_len);
  if (status != napi_ok || chunk_data == NULL || chunk_len == 0) {
    napi_throw_type_error(env, NULL, "chunk must be a non-empty Buffer or null");

    return NULL;
  }

  /* INFO: Ring buffer push with backpressure hint
   
           Non-blocking push. Returns the count of items remaining in the
             queue AFTER the push. This tells JS whether to pause the stream:
             if count >= HIGH_WATER (42/48), the JS 'data' handler should
             call rawStream.pause() to create backpressure through the pipeline.
             When the loop drains below LOW_WATER (16/48), the JS 'data' handler
             should call rawStream.resume().
   
           This avoids blocking the event loop entirely while still providing
             natural backpressure.
  */
  cthreads_mutex_lock(&nc->audio_mutex);

  /* If queue is entirely full, drop oldest as emergency fallback */
  if (nc->audio_q.count >= AUDIO_QUEUE_SIZE) {
    nc->audio_q.head = (nc->audio_q.head + 1) % AUDIO_QUEUE_SIZE;
    nc->audio_q.count--;
    nc->audio_q.dropped++;
  }

  size_t copy_len = chunk_len;
  if (copy_len > VOICE_MAX_PACKET_SIZE) copy_len = VOICE_MAX_PACKET_SIZE;

  memcpy(nc->audio_q.data[nc->audio_q.tail], chunk_data, copy_len);
  nc->audio_q.len[nc->audio_q.tail] = copy_len;
  nc->audio_q.tail = (nc->audio_q.tail + 1) % AUDIO_QUEUE_SIZE;
  nc->audio_q.count++;

  unsigned after_push = nc->audio_q.count;

  cthreads_cond_signal(&nc->audio_cond);

  cthreads_mutex_unlock(&nc->audio_mutex);

  /* INFO: Return the queue count after push so JS can manage backpressure */
  napi_create_uint32(env, after_push, &args[0]);

  return args[0];
}

/* INFO: stopSendLoop(ctx) */
static napi_value stop_send_loop(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  stop_loop_and_join(nc);

  napi_get_undefined(env, &args[0]);

  return args[0];
}

/* INFO: setStatsCallback(ctx, fn) */
static napi_value set_stats_callback(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(2)

  napi_valuetype t;
  napi_typeof(env, args[1], &t);
  if (t != napi_function) {
    napi_throw_type_error(env, NULL, "Second argument must be a function");

    return NULL;
  }

  /* INFO: If we already have a TSFN, release it first */
  if (nc->stats_tsfn != NULL) {
    napi_release_threadsafe_function(nc->stats_tsfn, napi_tsfn_abort);
    nc->stats_tsfn = NULL;
  }

  /* INFO: Async resource name */
  napi_value resource_name;
  napi_create_string_utf8(env, "voice-stats-sync", NAPI_AUTO_LENGTH, &resource_name);

  status = napi_create_threadsafe_function(
    env,
    args[1],        /* func */
    NULL,           /* async_resource */
    resource_name,  /* async_resource_name */
    0,              /* max_queue_size (unlimited) */
    1,              /* initial_thread_count */
    NULL,           /* thread_finalize_data */
    NULL,           /* thread_finalize_cb */
    (void *)nc,     /* context */
    NULL,           /* call_js_cb (direct call) */
    &nc->stats_tsfn
  );
  if (status != napi_ok) {
    nc->stats_tsfn = NULL;
    napi_throw_error(env, NULL, "Failed to create threadsafe function");

    return NULL;
  }

  nc->stats_counter = 0;

  napi_get_undefined(env, &args[0]);

  return args[0];
}

/* INFO: encrypt(context, audioChunk): Buffer */
static napi_value encrypt(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(2)

  void *chunk_data;
  size_t chunk_len;
  status = napi_get_buffer_info(env, args[1], &chunk_data, &chunk_len);
  if (status != napi_ok || chunk_data == NULL || chunk_len == 0) {
    napi_throw_type_error(env, NULL, "audioChunk must be a non-empty Buffer");

    return NULL;
  }

  uint8_t packet[VOICE_MAX_PACKET_SIZE];
  int pkt_len = voice_send_encrypt(&nc->ctx, (const uint8_t *)chunk_data, chunk_len, packet, sizeof(packet));
  if (pkt_len < 0) {
    napi_value result;
    napi_get_null(env, &result);

    return result;
  }

  napi_value result;
  status = napi_create_buffer_copy(env, (size_t)pkt_len, packet, NULL, &result);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "napi_create_buffer_copy failed");

    return NULL;
  }

  return result;
}

/* INFO: destroyContext(context) */
static napi_value destroy_context(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  stop_loop_and_join(nc);

  status = napi_remove_wrap(env, args[0], (void **)&nc);
  if (status == napi_ok && nc != NULL) {
    destroy_loop_fields(nc);
    voice_send_destroy(&nc->ctx);
    free(nc);
  }

  napi_get_undefined(env, &args[0]);

  return args[0];
}

static inline napi_value get_sequence(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  napi_value result;
  napi_create_uint32(env, voice_send_sequence(&nc->ctx), &result);

  return result;
}

static inline napi_value get_timestamp(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  napi_value result;
  napi_create_uint32(env, voice_send_timestamp(&nc->ctx), &result);

  return result;
}

static inline napi_value get_nonce(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  napi_value result;
  napi_create_uint32(env, voice_send_nonce(&nc->ctx), &result);

  return result;
}

static napi_value reset_nonce(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(2)

  uint32_t nonce;
  NAPI_GET_VALUE(nonce, 1, uint32)

  voice_send_reset_nonce(&nc->ctx, nonce);

  napi_get_undefined(env, &args[0]);

  return args[0];
}

/* INFO: getQueueCount(ctx) */
static napi_value get_queue_count(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  cthreads_mutex_lock(&nc->audio_mutex);
  unsigned count = nc->audio_q.count;
  cthreads_mutex_unlock(&nc->audio_mutex);

  napi_value result;
  napi_create_uint32(env, count, &result);

  return result;
}

/* INFO: getQueueDropped(ctx) */
static napi_value get_queue_dropped(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  cthreads_mutex_lock(&nc->audio_mutex);
  unsigned dropped = nc->audio_q.dropped;
  cthreads_mutex_unlock(&nc->audio_mutex);

  napi_value result;
  napi_create_uint32(env, dropped, &result);

  return result;
}

/* INFO: getStatistics(ctx): { sent, lost, expected } */
static napi_value get_statistics(napi_env env, napi_callback_info info) {
  NAPI_INIT_FN_INFO(1)

  struct voice_send_stats st = voice_send_stats(&nc->ctx);

  napi_value result;
  status = napi_create_object(env, &result);
  if (status != napi_ok) return NULL;

  napi_value v;
  napi_create_uint32(env, (uint32_t)st.packets_sent, &v);
  napi_set_named_property(env, result, "sent", v);

  napi_create_uint32(env, (uint32_t)st.packets_lost, &v);
  napi_set_named_property(env, result, "lost", v);

  napi_create_uint32(env, (uint32_t)st.packets_expected, &v);
  napi_set_named_property(env, result, "expected", v);

  return result;
}

/* INFO: Module exports */

#define EXPORT(name, func)                                                     \
  status = napi_create_function(env, name, NAPI_AUTO_LENGTH, func, NULL, &fn); \
  if (status != napi_ok) return NULL;                                          \
                                                                               \
  status = napi_set_named_property(env, exports, name, fn);                    \
  if (status != napi_ok) return NULL;

static napi_value init_module(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  EXPORT("createContext",    create_context);
  EXPORT("encrypt",          encrypt);
  EXPORT("destroyContext",   destroy_context);
  EXPORT("getSequence",      get_sequence);
  EXPORT("getTimestamp",     get_timestamp);
  EXPORT("getNonce",         get_nonce);
  EXPORT("resetNonce",       reset_nonce);
  EXPORT("startSendLoop",    start_send_loop);
  EXPORT("pushAudio",        push_audio);
  EXPORT("stopSendLoop",     stop_send_loop);
  EXPORT("getQueueCount",    get_queue_count);
  EXPORT("getQueueDropped",  get_queue_dropped);
  EXPORT("getStatistics",    get_statistics);
  EXPORT("setStatsCallback", set_stats_callback);

  napi_value mode;
  napi_create_object(env, &mode);

  napi_value v;
  napi_create_int32(env, VOICE_ENCRYPTION_AES256_GCM, &v);
  napi_set_named_property(env, mode, "AES256_GCM", v);

  napi_create_int32(env, VOICE_ENCRYPTION_XCHACHA20, &v);
  napi_set_named_property(env, mode, "XCHACHA20", v);

  napi_set_named_property(env, exports, "encryptionMode", mode);

  return exports;
}

#undef EXPORT

NAPI_MODULE(NODE_GYP_MODULE_NAME, init_module)
