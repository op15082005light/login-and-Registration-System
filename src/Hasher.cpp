// ============================================================================
//  Hasher.cpp — SHA-256 implementation (FIPS 180-4) + salted password hashing
// ============================================================================

#include "Hasher.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

// Out-of-line definition required for pre-C++17 linkers
constexpr std::array<uint32_t, 64> Hasher::K;

// ---------------------------------------------------------------------------
//  SHA-256 helper bit operations
// ---------------------------------------------------------------------------
uint32_t Hasher::rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
uint32_t Hasher::ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
uint32_t Hasher::maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
uint32_t Hasher::sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
uint32_t Hasher::sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
uint32_t Hasher::gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
uint32_t Hasher::gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

// ---------------------------------------------------------------------------
//  Full SHA-256 digest
// ---------------------------------------------------------------------------
std::array<uint8_t, Hasher::DIGEST_SIZE> Hasher::sha256(const std::string& input) {
    uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

    const uint64_t bitLen = static_cast<uint64_t>(input.size()) * 8;
    std::string msg = input;
    msg.push_back(static_cast<char>(0x80));
    while ((msg.size() % BLOCK_SIZE) != 56) {
        msg.push_back(0x00);
    }
    for (int i = 56; i >= 0; i -= 8) {
        msg.push_back(static_cast<char>((bitLen >> i) & 0xFF));
    }

    for (size_t offset = 0; offset < msg.size(); offset += BLOCK_SIZE) {
        uint32_t W[64]{};
        for (int i = 0; i < 16; ++i) {
            W[i] = (static_cast<uint8_t>(msg[offset + 4*i])     << 24) |
                    (static_cast<uint8_t>(msg[offset + 4*i + 1]) << 16) |
                    (static_cast<uint8_t>(msg[offset + 4*i + 2]) <<  8) |
                    (static_cast<uint8_t>(msg[offset + 4*i + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = gamma1(W[i-2]) + W[i-7] + gamma0(W[i-15]) + W[i-16];
        }

        uint32_t a = h0, b = h1, c = h2, d = h3;
        uint32_t e = h4, f = h5, g = h6, h = h7;

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + ch(e,f,g) + K[i] + W[i];
            uint32_t t2 = sigma0(a) + maj(a,b,c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }

    std::array<uint8_t, DIGEST_SIZE> digest{};
    auto pack = [&](int idx, uint32_t val) {
        digest[idx]   = static_cast<uint8_t>(val >> 24);
        digest[idx+1] = static_cast<uint8_t>(val >> 16);
        digest[idx+2] = static_cast<uint8_t>(val >>  8);
        digest[idx+3] = static_cast<uint8_t>(val);
    };
    pack(0, h0);  pack(4, h1);  pack(8, h2);  pack(12, h3);
    pack(16,h4);  pack(20,h5);  pack(24,h6);  pack(28,h7);
    return digest;
}

// ---------------------------------------------------------------------------
//  Hex encoding
// ---------------------------------------------------------------------------
std::string Hasher::toHex(const std::array<uint8_t, DIGEST_SIZE>& digest) {
    std::ostringstream oss;
    for (auto byte : digest) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<unsigned>(byte);
    }
    return oss.str();
}

#include <chrono>

// ---------------------------------------------------------------------------
//  Public API
// ---------------------------------------------------------------------------
std::string Hasher::generateSalt() {
    // Seed using both random_device and high-resolution timer to guarantee
    // entropy even on platforms/compilers with pseudo-deterministic random_device
    static thread_local std::mt19937_64 gen([]() {
        std::random_device rd;
        uint64_t seed1 = rd();
        uint64_t seed2 = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count());
        return seed1 ^ (seed2 + 0x9e3779b97f4a7c15ULL + (seed1 << 6) + (seed1 >> 2));
    }());

    std::uniform_int_distribution<int> dist(0, 255);

    std::ostringstream oss;
    for (int i = 0; i < 16; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2) << dist(gen);
    }
    return oss.str();
}

std::string Hasher::hashPassword(const std::string& password,
                                  const std::string& salt) {
    return toHex(sha256(salt + password));
}

bool Hasher::verify(const std::string& password,
                    const std::string& salt,
                    const std::string& expectedHash) {
    const std::string computed = hashPassword(password, salt);
    if (computed.size() != expectedHash.size()) return false;
    volatile int diff = 0;
    for (size_t i = 0; i < computed.size(); ++i) {
        diff |= (computed[i] ^ expectedHash[i]);
    }
    return diff == 0;
}
