#ifndef SHA_HEADER
#define SHA_HEADER

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t

struct internal_state
{
    union
    {
        u32 state[5];
        struct
        {
            u32 A;
            u32 B;
            u32 C;
            u32 D;
            u32 E;
        };
    };
};

static void panic(const char* mex)
{
    printf(mex);
    exit(-1);
}


static void initialize_state(struct internal_state* s)
{
    s->A = 0x67452301;
    s->B = 0xEFCDAB89;
    s->C = 0x98BADCFE;
    s->D = 0x10325476;
    s->E = 0xC3D2E1F0;
}

void print_state(struct internal_state state)
{
    printf("%x", state.A);
    printf("%x", state.B);
    printf("%x", state.C);
    printf("%x", state.D);
    printf("%x\n", state.E);
}

static u32 round_constants[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

u32 left_rotate(u32 word, u8 n)
{
    if(!n)return word;

    u32 temp = (word >> (32 - n));
    u32 res = (word << n) | temp;
    return res;
}

u32 to_big_endian(u32 val)
{
    u32 res = 0;
    u8 mask = 0xFF;
    u8 leftmost = val >> 24;
    u8 left = (val >> 16) & mask;
    u8 right = (val >> 8) & mask;
    u8 rightmost = val & mask;
    return rightmost << 24 | right << 16 | left << 8 | leftmost;
}

static void sha1_block(u32* block, struct internal_state* state)
{

    u32 words[80];
    u32 temp;
    u32 a = state->A;
    u32 b = state->B;
    u32 c = state->C;
    u32 d = state->D;
    u32 e = state->E;

    for(u32 i = 0; i < 16; ++i)
    {
        words[i] = to_big_endian(*(block + i));
    }

    for(u32 i = 16; i < 80; ++i)
    {
        temp = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
        words[i] = left_rotate(temp, 1);
    }

    for(u32 i = 0; i < 80; ++i)
    {
        u32 k = round_constants[i / 20];
        u32 w = words[i];
        int f;
        if (i < 20)
            f = (b & c) | ((~b) & d);
        else if (i < 40)
            f = b ^ c ^ d;
        else if (i < 60)
            f = (b & c) | (b & d) | (c & d);
        else
            f = b ^ c ^ d;

        temp = left_rotate(a, 5) + f + e + w + k;
        e = d;
        d = c;
        c = left_rotate(b, 30);
        b = a;
        a = temp;
    }

    state->A += a;
    state->B += b;
    state->C += c;
    state->D += d;
    state->E += e;

}


#include <string.h>
#define u64 uint64_t

static void print_buf(u8* buf, u32 size)
{
    printf("Size: %d\n", size);
    for(u32 i = 0; i < size; ++i)
    {
        printf("%x", buf[i]);
    }
    printf("\n");
}

static inline u32 max(u32 a, u32 b)
{
    return a > b ? a : b;
}

struct internal_state sha1(u8* file, u32 size)
{
    struct internal_state state;
    initialize_state(&state);


    u32 block_count;
    u32 remaining_bytes;

    if (size % 64)
    {
        block_count = size / 64 + 1;
        remaining_bytes = 64 - size % 64;
    }
    else
    {
        block_count = size / 64;
        remaining_bytes = 0;
    }

    int extra_block = 0;
    u8* buf = nullptr;
    
    if (remaining_bytes <= 8)
    {
        extra_block = 1;
        block_count++;
    }

    buf = new u8[size + remaining_bytes + 64 * extra_block];
    memset(buf, 0, size + remaining_bytes + 64 * extra_block);
    memcpy(buf, file, size);

//padding
    
    buf[size] = 0x80;
    u64 temp = (8 * (u64)size);
    for (int i = 0; i < 8; ++i)
    {
        buf[size + remaining_bytes + 64 * extra_block - (8 - i)] = (u8)(temp >> ((7 - i) * 8));
    }
    
    
    for(u32 i = 0; i < block_count; ++i)
    {
        sha1_block((u32*)(buf + 64 * i), &state);
    }

    return state;
}


#endif
