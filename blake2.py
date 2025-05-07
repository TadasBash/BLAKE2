import struct

# Rotacija į dešinę (32 bitų)
def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# G funkcija pagal RFC 7693
def G(v, a, b, c, d, x, y):
    v[a] = (v[a] + v[b] + x) & 0xFFFFFFFF
    v[d] = rotr32(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFF
    v[b] = rotr32(v[b] ^ v[c], 12)
    v[a] = (v[a] + v[b] + y) & 0xFFFFFFFF
    v[d] = rotr32(v[d] ^ v[a], 8)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFF
    v[b] = rotr32(v[b] ^ v[c], 7)

# Sigma – permutacijos lentele
SIGMA = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
]

# Pradinės konstantos (IV)
IV = [
    0x6A09E667, 0xBB67AE85,
    0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C,
    0x1F83D9AB, 0x5BE0CD19
]

# Kompresavimo funkcija
def compress(h, m, t, f):
    v = h[:] + IV[:]
    v[12] ^= t & 0xFFFFFFFF
    v[13] ^= (t >> 32) & 0xFFFFFFFF
    if f:
        v[14] ^= 0xFFFFFFFF

    m_words = struct.unpack('<16I', m)
    for i in range(10):  # 10 raundų
        s = SIGMA[i % 10]
        G(v, 0, 4, 8, 12, m_words[s[0]], m_words[s[1]])
        G(v, 1, 5, 9, 13, m_words[s[2]], m_words[s[3]])
        G(v, 2, 6, 10, 14, m_words[s[4]], m_words[s[5]])
        G(v, 3, 7, 11, 15, m_words[s[6]], m_words[s[7]])
        G(v, 0, 5, 10, 15, m_words[s[8]], m_words[s[9]])
        G(v, 1, 6, 11, 12, m_words[s[10]], m_words[s[11]])
        G(v, 2, 7, 8, 13, m_words[s[12]], m_words[s[13]])
        G(v, 3, 4, 9, 14, m_words[s[14]], m_words[s[15]])

    for i in range(8):
        h[i] ^= v[i] ^ v[i + 8]

# BLAKE2s maišos algoritmas
def blake2s(data: bytes, digest_size: int = 32) -> bytes:
    h = IV[:]
    h[0] ^= 0x01010000 ^ digest_size

    block_size = 64
    t = 0
    offset = 0
    while offset + block_size <= len(data):
        block = data[offset:offset + block_size]
        t += block_size
        compress(h, block, t, False)
        offset += block_size

    # Paskutinis blokas
    last_block = data[offset:]
    last_block += b'\x00' * (block_size - len(last_block))
    t += len(data) - offset
    compress(h, last_block, t, True)

    digest = b''.join(struct.pack('<I', x) for x in h)
    return digest[:digest_size]
