#include <stdint.h>
#include <sys/random.h>
#include <stdio.h>

#define UUID_TS_OFFSET 122192928000000000LL // Amount of 100-nanosecond intervals before the Unix epoch on midnight 15 Oct 1582
#define INT14_MAX 16383
#define UUID_STR_LEN 37
#define UUID_LEN 36
#define HEX_DIGITS "0123456789abcdefABCDEF"

// 128 bits to store the UUID in numerical form
typedef struct {
    uint64_t high, low;
} uuid_t;

// Used for storing the UUID generator state
typedef struct {
    uint64_t last_ts, curr_ts, node_id;
    int16_t clock_seq;
    uint8_t initialized; // Set to 1 if initialized, 0 otherwise
} uuidv1_state_t;

char * uuidv4_gen(char *buf);
char * uuidv1_gen(char *buf, uuidv1_state_t *generator_state);