#include "uuid.h"
#include <bits/time.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>

// Return a timestamp in UUIDv1 format (amount of 100-nanoseconds intervals since 00:00:00.00, 15 October 1582)
uint64_t get_uuid_timestamp(){
    struct timespec curr_time;
    uint64_t ts;

    clock_gettime(CLOCK_REALTIME, &curr_time);
    ts = (curr_time.tv_nsec * 10000000) + (curr_time.tv_nsec / 100) + UUID_TS_OFFSET;

    return ts;
}

void init_generator_state(uuidv1_state_t *state){
    state->last_ts = state->node_id = 0;
    state->clock_seq = -1;
}

// Return 1 (true) if a UUID is in a valid format, otherwise return 0
uint8_t is_valid_uuid(char *uuid){
    if(strlen(uuid) != UUID_LEN)
        return 0;

    char uuid_copy[UUID_STR_LEN];
    strncpy(uuid_copy, uuid, UUID_LEN);
    uuid_copy[UUID_LEN] = '\0';

    char *save_ptr, *token;
    if((token = strtok_r(uuid_copy, "-", &save_ptr)) == NULL || strlen(token) != 8 || strspn(token, HEX_DIGITS) != strlen(token))
        return 0;

    for(uint8_t i = 0; i < 3; i++)
        if((token = strtok_r(NULL, "-", &save_ptr)) == NULL || strlen(token) != 4 || strspn(token, HEX_DIGITS) != strlen(token))
            return 0;

    if((token = strtok_r(NULL, "-", &save_ptr)) == NULL || strlen(token) != 12 || strspn(token, HEX_DIGITS) != strlen(token))
        return 0;

    return 1;
}

// Convert a UUID that's in string format to its binary representation as two 64 bit fields
void uuid_str_to_binary(char *s, uuid_t *uuid){
    uuid->high = strtoull(s, NULL, 16) << 32;
    uuid->high |= strtoull(s + 9, NULL, 16) << 16;
    uuid->high |= strtoull(s + 14, NULL, 16);

    uuid->low = strtoull(s + 19, NULL, 16) << 48;
    uuid->low |= strtoull(s + 24, NULL, 16);
}

// BUF must be at least 37 characters long
// Return a pointer to BUF on success or NULL on failure
char * uuidv1_gen(char *buf, uuidv1_state_t *generator_state){
    uuid_t uuid;

    if(buf == NULL || generator_state == NULL)
        return NULL;

    if(!generator_state->initialized){
        if(getrandom(&generator_state->clock_seq, sizeof(generator_state->clock_seq), 0) == -1) // First UUID being generated, initialize clock sequence.
            return NULL;

        if(getrandom(&generator_state->node_id, sizeof(generator_state->node_id), 0) == -1) // First UUID being generated, initialize node id.
            return NULL;
    }

    generator_state->curr_ts = get_uuid_timestamp();

    uuid.high = generator_state->curr_ts << 32; // Set time_low field
    uuid.high |= (generator_state->curr_ts & 0x0000FFFF00000000UL) >> 16; // Set time_mid field
    uuid.high |= (generator_state->curr_ts & 0xFFFF000000000000UL) >> 48; // Set time_high field

    // Set version field to 1 (bits 48 through 51)
    uuid.high = (uuid.high & 0xFFFFFFFFFFFF0FFFUL) | (1UL << 12);

    // Set node id
    uuid.low = generator_state->node_id;

    // Set clock sequence and var field (0b10)
    uuid.low = (uuid.low & 0x0000FFFFFFFFFFFFUL) | (uint64_t) (((generator_state->curr_ts > generator_state->last_ts ? generator_state->clock_seq : ++generator_state->clock_seq) & 0x3fff) | 0x8000) << 48;
    generator_state->last_ts = generator_state->curr_ts;

    // Set multicast bit in node id
    uuid.low |= 0x0000010000000000UL;

    // Convert to string
    snprintf(buf, UUID_STR_LEN, "%08lx-%04lx-%04lx-%04lx-%012lx", (uuid.high >> 32) & 0x00000000FFFFFFFFUL, (uuid.high >> 16) & 0x000000000000FFFFUL, uuid.high & 0x000000000000FFFFUL, (uuid.low >> 48) & 0x000000000000FFFFUL, uuid.low & 0x0000FFFFFFFFFFFFUL);

    return buf;
}

// NAMESPACE must be provided in the UUID string format.
// BUF must be at least 37 characters long
// Return a pointer to BUF on success or NULL on failure
char * uuidv3_gen(char *buf, char *namespace, char *name){
    uuid_t namespace_bin; // NAMESPACE UUID in binary form
    uint8_t digest[EVP_MAX_MD_SIZE];
    uint32_t digest_len;

    if(buf == NULL || name == NULL || !is_valid_uuid(namespace))
        return NULL;

    uuid_str_to_binary(namespace, &namespace_bin);
    namespace_bin.high = htobe64(namespace_bin.high);
    namespace_bin.low = htobe64(namespace_bin.low);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
        return NULL;

    if(
        !EVP_DigestInit(ctx, EVP_md5()) ||
        !EVP_DigestUpdate(ctx, &namespace_bin, sizeof(namespace_bin)) ||
        !EVP_DigestUpdate(ctx, name, strlen(name)) ||
        !EVP_DigestFinal(ctx, digest, &digest_len)
    ) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);

    digest[6] = (digest[6] & 0x0F) | 0x30;
    digest[8] = (digest[8] & 0x3F) | 0x80;

    snprintf(buf, UUID_STR_LEN, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);

    return buf;
}

// NAMESPACE must be provided in the UUID string format.
// BUF must be at least 37 characters long
// Return a pointer to BUF on success or NULL on failure
char * uuidv5_gen(char *buf, char *namespace, char *name){
    uuid_t namespace_bin; // NAMESPACE UUID in binary form
    uint8_t digest[EVP_MAX_MD_SIZE];
    uint32_t digest_len;

    if(buf == NULL || name == NULL || !is_valid_uuid(namespace))
        return NULL;

    uuid_str_to_binary(namespace, &namespace_bin);
    namespace_bin.high = htobe64(namespace_bin.high);
    namespace_bin.low = htobe64(namespace_bin.low);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(ctx == NULL)
        return NULL;

    if(
        !EVP_DigestInit(ctx, EVP_sha1()) ||
        !EVP_DigestUpdate(ctx, &namespace_bin, sizeof(namespace_bin)) ||
        !EVP_DigestUpdate(ctx, name, strlen(name)) ||
        !EVP_DigestFinal(ctx, digest, &digest_len)
    ) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);
    digest[6] = (digest[6] & 0x0F) | 0x50;
    digest[8] = (digest[8] & 0x3F) | 0x80;

    snprintf(buf, UUID_STR_LEN, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7], digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15]);

    return buf;
}

// BUF must be at least 37 characters long
// Return a pointer to BUF on success or NULL on failure
char * uuidv4_gen(char *buf){
    uuid_t uuid;

    if(getrandom(&uuid, sizeof(uuid_t), 0) == -1)
        return NULL;

    // Set version field to 4 (bits 58 through 51 from the left)
    uuid.high = (uuid.high & 0xFFFFFFFFFFFF0FFFUL) | (4UL << 12);

    // Set variant field to 2 (bits 64 and 65)
    uuid.low = (uuid.low & 0x3FFFFFFFFFFFFFFFUL) | (2UL << 62);

    // Convert to string
    snprintf(buf, UUID_STR_LEN, "%08lx-%04lx-%04lx-%04lx-%012lx", (uuid.high >> 32) & 0x00000000FFFFFFFFUL, (uuid.high >> 16) & 0x000000000000FFFFUL, uuid.high & 0x000000000000FFFFUL, (uuid.low >> 48) & 0x000000000000FFFFUL, uuid.low & 0x0000FFFFFFFFFFFFUL);

    return buf;
}

// BUF must be at least 37 characters long
// Return a pointer to BUF on success or NULL on failure
char * uuidv6_gen(char *buf){
    uuid_t uuid;

    uuid.high = get_uuid_timestamp();

    // Set version field to 6 (bits 48 through 51)
    uuid.high = (uuid.high & 0xFFFFFFFFFFFF0FFFUL) | (6UL << 12);

    // Set clock_seq and node to a randomized value
    if(getrandom(&uuid.low, sizeof(uuid.low), 0) == -1)
        return NULL;

    // Set var field (0b10)
    uuid.low = (uuid.low & 0x3FFFFFFFFFFFFFFFUL) | (2UL << 62);

    // Set multicast bit in node id
    uuid.low |= 0x0000010000000000UL;

    // Convert to string
    snprintf(buf, UUID_STR_LEN, "%08lx-%04lx-%04lx-%04lx-%012lx", (uuid.high >> 32) & 0x00000000FFFFFFFFUL, (uuid.high >> 16) & 0x000000000000FFFFUL, uuid.high & 0x000000000000FFFFUL, (uuid.low >> 48) & 0x000000000000FFFFUL, uuid.low & 0x0000FFFFFFFFFFFFUL);

    return buf;
}

// BUF must be at least 37 characters long
// Return a pointer to BUF on success or NULL on failure
char *uuidv7_gen(char *buf){
    struct timespec ts;
    uuid_t uuid;

    if(getrandom(&uuid, sizeof(uuid), 0) == -1)
        return NULL;

    clock_gettime(CLOCK_REALTIME, &ts);
    uuid.high &= 0x000000000000FFFFULL;
    uuid.high = ((uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000) << 16 | uuid.high; // Write 48 MSBs of timestamp in big endian format

    // Set version field to 7
    uuid.high = (uuid.high & 0xFFFFFFFFFFFF0FFFULL) | (7ULL << 12);

    // Set var field (0b10)
    uuid.low = (uuid.low & 0x3FFFFFFFFFFFFFFFUL) | (2ULL << 62);

    // Convert to string
    snprintf(buf, UUID_STR_LEN, "%08lx-%04lx-%04lx-%04lx-%012lx", (uuid.high >> 32) & 0x00000000FFFFFFFFUL, (uuid.high >> 16) & 0x000000000000FFFFUL, uuid.high & 0x000000000000FFFFUL, (uuid.low >> 48) & 0x000000000000FFFFUL, uuid.low & 0x0000FFFFFFFFFFFFUL);

    return buf;
}