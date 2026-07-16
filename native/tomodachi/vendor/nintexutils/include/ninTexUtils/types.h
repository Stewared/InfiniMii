#pragma once

#ifndef forceinline
    #ifdef _MSC_VER
        #define forceinline __forceinline
    #else
        #define forceinline __attribute__((always_inline)) inline
    #endif
#endif // forceinline

// Hard-coded for now
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || !defined(__ORDER_BIG_ENDIAN__)
    // Define these in MSVC
    #ifdef _MSC_VER
        // NOTE: assuming little endian
        // ... MSVC only targets x86, ARM anyway, all little endian
        #define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
        #define __ORDER_LITTLE_ENDIAN__ 1234
        #define __ORDER_BIG_ENDIAN__ 4321
    #else
        #error "Need __BYTE_ORDER__, __ORDER_LITTLE_ENDIAN__ and __ORDER_BIG_ENDIAN__ to be defined"
    #endif
#endif

#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ && __BYTE_ORDER__ != __ORDER_BIG_ENDIAN__)
    #error "Host must be either big- or little-endian"
#endif

#ifdef _WIN32
    #if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
        #error "Need Windows 32-bit platform to be little-endian!"
    #endif
#endif // _WIN32

#if (defined(__cplusplus) && __cplusplus < 201103L) || (!defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L))
    #if !defined(static_assert) && !defined(_MSC_VER)
        // https://stackoverflow.com/a/1597129
        #ifdef NDEBUG
            #define TOKENPASTE(x, y) x ## y
            #define TOKENPASTE2(x, y) TOKENPASTE(x, y)
            #define static_assert(condition, ...) typedef int TOKENPASTE2(static_assert_, __LINE__)[(condition) ? 1 : -1]
        #else
            #define static_assert(...) ((void)0)
        #endif
    #endif // static_assert

    #include <stdint.h>
#else
    #ifdef __cplusplus
        #include <cassert>
        #include <cstdint>
        #ifdef NDEBUG
              #define static_assert(...) static_assert(true, "")
        #endif
    #else
        #include <assert.h>
        #include <stdint.h>
    #endif
#endif

#ifdef __cplusplus
    #include <cstddef>
#else
    #include <stddef.h>
    #include <stdbool.h>
#endif

typedef  int8_t s8;
typedef uint8_t u8;

typedef  int16_t s16;
typedef uint16_t u16;

typedef  int32_t s32;
typedef uint32_t u32;

typedef  int64_t s64;
typedef uint64_t u64;

typedef float  f32;
typedef double f64;

// static_assert32 = static_assert but only applies for 32 bit
#if defined(NDEBUG) || INTPTR_MAX == INT64_MAX
		#define static_assert32(...) static_assert(true, "")
#else
		#define static_assert32 static_assert
#endif

static_assert(sizeof(s8)  == sizeof(u8)  && sizeof(u8)  == sizeof(char) && sizeof(char) == 1);
static_assert(sizeof(s16) == sizeof(u16) && sizeof(u16) == 2);
static_assert(sizeof(s32) == sizeof(u32) && sizeof(u32) == 4);
static_assert(sizeof(s64) == sizeof(u64) && sizeof(u64) == 8);
static_assert(sizeof(f32) == 4);
static_assert(sizeof(f64) == 8);

#if defined(_WIN32) && !defined(BOOL)
    #define BOOL int
#endif

#ifdef _MSC_VER
    #include <stdlib.h>
    static inline unsigned long __builtin_bswap32(unsigned long x)
    {
        return _byteswap_ulong(x);
    }
    static inline unsigned long long __builtin_bswap64(unsigned long long x)
    {
        return _byteswap_uint64(x);
    }
#endif
