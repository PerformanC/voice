#ifndef VOICE_UTILS_H
#define VOICE_UTILS_H

#define NAPI_GET_VALUE_EXTRA(name, idx, type, extra_check, str)               \
  status = napi_get_value_ ## type(env, args[idx], &name);                    \
  if (status != napi_ok || !(extra_check)) {                                  \
    napi_throw_type_error(env, NULL, #name " must be a " #type " and " #str); \
                                                                              \
    return NULL;                                                              \
  }

#define NAPI_GET_VALUE(name, idx, type) NAPI_GET_VALUE_EXTRA(name, idx, type, 1, "")

#define NAPI_UNWRAP_CTX(name)                            \
  status = unwrap_ctx(env, args[0], &name);              \
  if (status != napi_ok || name == NULL) {               \
    napi_throw_type_error(env, NULL, "Invalid context"); \
                                                         \
    return NULL;                                         \
  }

#define NAPI_GET_CB_INFO(args_len) \
  size_t argc = args_len;                                                    \
  napi_value args[args_len];                                                 \
  napi_status status = napi_get_cb_info(env, info, &argc, args, NULL, NULL); \
  if (status != napi_ok || argc < args_len) {                                \
    napi_throw_type_error(env, NULL, "Expected " #args_len " arguments");    \
                                                                             \
    return NULL;                                                             \
  }

#define NAPI_INIT_FN_INFO(args_len) \
  NAPI_GET_CB_INFO(args_len)        \
                                    \
  struct native_ctx *nc;            \
  NAPI_UNWRAP_CTX(nc)

#endif /* VOICE_UTILS_H */
