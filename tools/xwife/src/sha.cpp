#include "sha.hpp"

// I'm not reverse engineering SHA-256. I just wrote all this.

static unsigned int Sha256RotR(unsigned int value, unsigned int bits) {
    return (value >> bits) | (value << (32 - bits));
}

static unsigned int Sha256LoadBE32(unsigned char const *data) {
    return (static_cast<unsigned int>(data[0]) << 24) |
           (static_cast<unsigned int>(data[1]) << 16) |
           (static_cast<unsigned int>(data[2]) << 8) |
           static_cast<unsigned int>(data[3]);
}

static void Sha256StoreBE32(unsigned char *data, unsigned int value) {
    data[0] = static_cast<unsigned char>(value >> 24);
    data[1] = static_cast<unsigned char>(value >> 16);
    data[2] = static_cast<unsigned char>(value >> 8);
    data[3] = static_cast<unsigned char>(value);
}

static void Sha256Transform(unsigned int state[8], unsigned char const block[64]) {
    static constexpr unsigned int k[64] = {
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    unsigned int w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = Sha256LoadBE32(block + i * 4);
    for (int i = 16; i < 64; ++i) {
        unsigned int s0 = Sha256RotR(w[i - 15], 7) ^ Sha256RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = Sha256RotR(w[i - 2], 17) ^ Sha256RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    unsigned int e = state[4];
    unsigned int f = state[5];
    unsigned int g = state[6];
    unsigned int h = state[7];

    for (int i = 0; i < 64; ++i) {
        unsigned int s1 = Sha256RotR(e, 6) ^ Sha256RotR(e, 11) ^ Sha256RotR(e, 25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int temp1 = h + s1 + ch + k[i] + w[i];
        unsigned int s0 = Sha256RotR(a, 2) ^ Sha256RotR(a, 13) ^ Sha256RotR(a, 22);
        unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
        unsigned int temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// ?XLivepComputeSHA256Digest@@YGJPBEKPAE@Z
HRESULT XLivepComputeSHA256Digest(unsigned char const *data, unsigned long data_size, unsigned char *digest) {
    if (!digest || (!data && data_size))
        return E_INVALIDARG;

    unsigned int state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    unsigned long remaining = data_size;
    while (remaining >= 64) {
        Sha256Transform(state, data);
        data += 64;
        remaining -= 64;
    }

    unsigned char block[64];
    for (int i = 0; i < 64; ++i)
        block[i] = 0;
    for (unsigned long i = 0; i < remaining; ++i)
        block[i] = data[i];
    block[remaining] = 0x80;

    if (remaining >= 56) {
        Sha256Transform(state, block);
        for (int i = 0; i < 64; ++i)
            block[i] = 0;
    }

    unsigned long long bit_count = static_cast<unsigned long long>(data_size) * 8ULL;
    for (int i = 0; i < 8; ++i)
        block[63 - i] = static_cast<unsigned char>(bit_count >> (i * 8));

    Sha256Transform(state, block);

    for (int i = 0; i < 8; ++i)
        Sha256StoreBE32(digest + i * 4, state[i]);

    return ERROR_SUCCESS;
}
