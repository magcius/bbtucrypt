/* CFLAGS="-std=c99 -Wall -Werror" make decrypt */

/* Decrypts the encrypted audio files in BattleBlock Theater. 
 * Nice job, Tom Fulp. This one took me quite a while to figure out. 
 * Also, we're all waiting for the official soundtrack release.
 *
 *   - Jasper
 */

#include <assert.h>
#include <ctype.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define be32(x) (__builtin_bswap32((x)))
#define NELEM(x) (sizeof ((x)) / sizeof (*(x)))

/* Standard Mersenne Twister */
struct MersenneTwister {
    uint32_t state[624];
    size_t index;
};

static void mtwist_seed (struct MersenneTwister *twist, uint32_t seed) {
    twist->index = 0;
    twist->state[0] = seed;
    for (size_t i = 1; i < 624; i++)
        twist->state[i] = (i + 0x6C078965 * (twist->state[i - 1] ^ (twist->state[i - 1] >> 30))) & 0xFFFFFFFF;
}

static void mtwist_reseed (struct MersenneTwister *twist) {
    for (size_t i = 0; i < 624; i++) {
        uint32_t y = (twist->state[i] & 0x80000000) + (twist->state[(i + 1) % 624] & 0x7FFFFFFF);
        twist->state[i] = twist->state[(i + 397) % 624] ^ (y >> 1);
        if (y % 2 != 0)
            twist->state[i] ^= 0x9908B0DF;
    }
}

static uint32_t mtwist_next (struct MersenneTwister *twist) {
    if (twist->index == 0)
        mtwist_reseed (twist);

    uint32_t y = twist->state[twist->index];
    y ^= (y >> 11);
    y ^= (y <<  7) & 0x9D2C5680;
    y ^= (y << 15) & 0xEFC60000;
    y ^= (y >> 18);

    twist->index = (twist->index + 1) % 624;

    return y;
}

/* Get the seed for the RNG that generates the file key,
 * based on the track name. */
static uint32_t get_rand_seed (char *track_name) {
    /* Spike Lee's Birthday, I assume... */
    uint32_t seed = 0x19570320;
    for (size_t i = 0; *track_name; track_name++, i++) {
        char chr = *track_name;
        char m = chr >> (i & 3);
        seed = (seed * m) + chr;
    }
    return seed;
}

static void get_file_key (uint32_t key[4], char *track_name) {
    struct MersenneTwister rng;
    uint32_t seed = get_rand_seed (track_name);
    mtwist_seed (&rng, seed);

    for (size_t i = 0; i < 4; i++)
        key[i] = be32 (mtwist_next (&rng));
}

/* Find the track name from the filename. For Sounds/secret_music_01.wma,
 * this is "SECRET_MUSIC_01". This is used to generate the file key. */
static void get_track_name (char *buf, char *filename) {
    char *last_slash = strrchr (filename, '/');
    if (last_slash == NULL)
        last_slash = filename;

    char *last_dot = strrchr (filename, '.');
    assert (last_dot > last_slash);

    char *b = buf;
    for (char *n = last_slash; n < last_dot; n++, b++)
        *b = toupper (*n);
    *b = '\0';
}

struct Decrypter {
    uint32_t key1buf[0x12];
    uint32_t key2buf[0x1024];
};

static void decrypter_init (struct Decrypter *self, uint32_t *key1, uint32_t *key2) {
    memcpy (self->key1buf, key1, sizeof (self->key1buf));
    memcpy (self->key2buf, key2, sizeof (self->key2buf));
}

static void decrypter_descramble_work (struct Decrypter *self, uint32_t *a, uint32_t *b) {
    uint32_t v1, v2, v3, v4, v5;

    uint32_t *k1 = self->key1buf;
    uint32_t *k2 = self->key2buf;

    v5 = *a;
    v4 = *b;

    for (size_t i = 0; i < 16; i += 4) {
        v1 = (v5 ^ k1[i+0]);
        v2 = (v4 ^ k1[i+1] ^ (k2[(v1 & 0xFF) + 0x300] + (k2[((v1 >> 8) & 0xFF) + 0x200] ^ (k2[((v1 >> 16) & 0xFF) + 0x100] + k2[((v1 >> 24) & 0xFF)]))));
        v3 = (v1 ^ k1[i+2] ^ (k2[(v2 & 0xFF) + 0x300] + (k2[((v2 >> 8) & 0xFF) + 0x200] ^ (k2[((v2 >> 16) & 0xFF) + 0x100] + k2[((v2 >> 24) & 0xFF)]))));
        v4 = (v2 ^ k1[i+3] ^ (k2[(v3 & 0xFF) + 0x300] + (k2[((v3 >> 8) & 0xFF) + 0x200] ^ (k2[((v3 >> 16) & 0xFF) + 0x100] + k2[((v3 >> 24) & 0xFF)]))));
        v5 = (v3           ^ (k2[(v4 & 0xFF) + 0x300] + (k2[((v4 >> 8) & 0xFF) + 0x200] ^ (k2[((v4 >> 16) & 0xFF) + 0x100] + k2[((v4 >> 24) & 0xFF)]))));
    }

    *a = v4 ^ k1[17];
    *b = v5 ^ k1[16];
}

static void decrypter_descramble_keys (struct Decrypter *self) {
    /* Now start descrambling key1 / key2. */
    uint32_t a = 0, b = 0;
    for (size_t i = 0; i < NELEM (self->key1buf); i += 2) {
        decrypter_descramble_work (self, &a, &b);
        self->key1buf[i+0] = a;
        self->key1buf[i+1] = b;
    }

    for (size_t i = 0; i < NELEM (self->key2buf); i += 2) {
        decrypter_descramble_work (self, &a, &b);
        self->key2buf[i+0] = a;
        self->key2buf[i+1] = b;
    }
}

static void decrypter_decrypt_file (struct Decrypter *tmpl, char *input_filename, char *output_filename) {
    struct Decrypter _self;
    struct Decrypter *self = &_self;

    uint32_t file_key[4];
    char track_name[256];

    /* Copy over the original key data. */
    memcpy (self->key1buf, tmpl->key1buf, sizeof (self->key1buf));
    memcpy (self->key2buf, tmpl->key2buf, sizeof (self->key2buf));

    get_track_name (track_name, input_filename);
    get_file_key (file_key, track_name);

    /* Inject the track name into key1. */
    for (size_t i = 0; i < NELEM (self->key1buf); i++)
        self->key1buf[i] ^= file_key[i % NELEM (file_key)];

    /* Descramble the keys. */
    decrypter_descramble_keys (self);

    /* Now decrypt the file. */
    FILE *fin = fopen (input_filename, "rb");
    FILE *fout = fopen (output_filename, "wb");

    /* Skip past the checksum. We should probably verify this at some point... */
    fseek (fin, 24, SEEK_SET);

    /* Decrypt. */
    while (!feof (fin)) {
        uint32_t buf[2];
        fread (buf, sizeof (*buf), NELEM (buf), fin);

        uint32_t *k1 = self->key1buf;
        uint32_t *k2 = self->key2buf;

        uint32_t v1, v2, v3;
        v2 = buf[0];
        v3 = buf[1];

        for (size_t i = 0; i < 16; i++) {
            v1 = v2 ^ (k1[17 - i]);
            v2 = v3 ^ (k2[(v1 & 0xFF) + 0x300] + (k2[((v1 >> 8) & 0xFF) + 0x200] ^ (k2[((v1 >> 16) & 0xFF) + 0x100] + k2[((v1 >> 24) & 0xFF)])));
            v3 = v1;
        }

        buf[0] = v1 ^ k1[0];
        buf[1] = v2 ^ k1[1];

        fwrite (buf, sizeof (*buf), NELEM (buf), fout);
    }

    fclose (fin);
    fclose (fout);
}

/* Key data, extracted from the binary... */
#include "keys.inc"

int main(int argc, char *argv[]) {
    char *filename = argv[1];
    char *out;
    if (argc >= 3)
        out = argv[2];
    else
        out = "out.wma";

    printf ("Decrypting %s to %s...\n", filename, out);

    struct Decrypter decrypter;
    decrypter_init (&decrypter, key1_data, key2_data);

    decrypter_decrypt_file (&decrypter, filename, out);

    return 0;
}
