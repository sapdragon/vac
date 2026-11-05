// Copied verbatim from modules/process_memory_map/entry.cpp, the compressor the SDK copy has to match.
// Generated once, do not restyle: the module file gets migrated later and this stays the reference.
// clang-format off
vac::u32 lz4CompressBound(vac::u32 n) noexcept {
    if (n <= 0x7E000000u)
        return n + n / 255u + 16u;
    return 0;
}

vac::u32 lz4Hash(vac::u32 sequence, vac::u32 bits) noexcept {
    return (sequence * 2654435761u) >> ((kLz4MinMatch * 8u) - bits);
}

vac::u32 commonBytes(vac::u32 x) noexcept {
    if (!x) return 4;
    vac::u32 n = 0;
    while ((x & 0xFFu) == 0) {
        ++n;
        x >>= 8;
    }
    return n;
}

int lz4Compress(const vac::u8* src, vac::u8* dst, vac::u32 srcSize, vac::u32 dstCap) noexcept {
    if (!srcSize) return 0;
    if (lz4CompressBound(srcSize) > dstCap) return 0;

    vac::u16 table[1u << kLz4HashLog];
    memset(table, 0, sizeof(table));

    const vac::u8* const base = src;
    const vac::u8* const iend = src + srcSize;
    const vac::u8* const mflimit = iend - 11;
    const vac::u8* const matchlimit = iend - 5;
    const vac::u8* anchor = src;
    const vac::u8* ip = src + 1;
    vac::u32 forwardH = 0;
    vac::u8* op = dst;

    if (srcSize < 13u)
        goto last_literals;

    table[lz4Hash(vac::util::read32(src), kLz4HashLog)] = 0;
    forwardH = lz4Hash(vac::util::read32(ip), kLz4HashLog);

    for (;;) {
        const vac::u8* match;
        const vac::u8* forwardIp = ip;
        vac::u32 step = 1;
        vac::u32 searchMatchNb = 64;

        do {
            ip = forwardIp;
            forwardIp += step;
            step = searchMatchNb++ >> 6;
            if (forwardIp > mflimit)
                goto last_literals;

            const vac::u32 h = forwardH;
            const vac::u16 ref = table[h];
            match = base + ref;
            forwardH = lz4Hash(vac::util::read32(forwardIp), kLz4HashLog);
            table[h] = static_cast<vac::u16>(ip - base);
        } while ((ip - match > 0xFFFF) || vac::util::read32(match) != vac::util::read32(ip));

        while (ip > anchor && match > base && ip[-1] == match[-1]) {
            --ip;
            --match;
        }

        {
            vac::u32 litLen = static_cast<vac::u32>(ip - anchor);
            vac::u8* token = op++;
            if (litLen >= 15u) {
                *token = 15u << 4;
                vac::u32 len = litLen - 15u;
                if (len < 255u) {
                    *op++ = static_cast<vac::u8>(len);
                } else {
                    const vac::u32 blocks = len / 255u;
                    memset(op, 255, blocks);
                    op += blocks;
                    *op++ = static_cast<vac::u8>(len % 255u);
                }
            } else {
                *token = static_cast<vac::u8>(litLen << 4);
            }

            memcpy(op, const_cast<vac::u8*>(anchor), litLen);
            op += litLen;

            for (;;) {
                vac::util::write16(op, static_cast<vac::u16>(ip - match));
                op += 2;

                ip += kLz4MinMatch;
                match += kLz4MinMatch;

                const vac::u8* start = ip;
                while (ip < iend - 8) {
                    const vac::u32 diff = vac::util::read32(match) ^ vac::util::read32(ip);
                    if (diff) {
                        ip += commonBytes(diff);
                        goto match_done;
                    }
                    ip += 4;
                    match += 4;
                }
                if (ip < iend - 6 &&
                    *reinterpret_cast<const vac::u16*>(match) == *reinterpret_cast<const vac::u16*>(ip)) {
                    ip += 2;
                    match += 2;
                }
                if (ip < iend - 5 && *match == *ip)
                    ++ip;
match_done:
                {
                    vac::u32 matchLen = static_cast<vac::u32>(ip - start);
                    if (matchLen >= 15u) {
                        *token += 15u;
                        matchLen -= 15u;
                        vac::u32 ffs = 0xFFFFFFFFu;
                        memcpy(op, &ffs, 4);
                        if (matchLen >= 1020u) {
                            vac::u32 blocks = matchLen / 1020u;
                            do {
                                op += 4;
                                memcpy(op, &ffs, 4);
                                --blocks;
                            } while (blocks);
                            matchLen %= 1020u;
                        }
                        op += matchLen / 255u;
                        *op++ = static_cast<vac::u8>(matchLen % 255u);
                    } else {
                        *token = static_cast<vac::u8>(*token + matchLen);
                    }
                }

                anchor = ip;
                if (ip >= mflimit)
                    goto last_literals;

                table[lz4Hash(vac::util::read32(ip - 2), kLz4HashLog)] = static_cast<vac::u16>((ip - 2) - base);
                const vac::u32 h = lz4Hash(vac::util::read32(ip), kLz4HashLog);
                match = base + table[h];
                table[h] = static_cast<vac::u16>(ip - base);
                if (ip - match > 0xFFFF || vac::util::read32(match) != vac::util::read32(ip)) {
                    forwardH = lz4Hash(vac::util::read32(++ip), kLz4HashLog);
                    break;
                }
                token = op++;
                *token = 0;
            }
        }
    }

last_literals:
    {
        const vac::u32 litLen = static_cast<vac::u32>(iend - anchor);
        if (!litLen)
            return static_cast<int>(op - dst);
        vac::u8* token = op++;
        if (litLen >= 15u) {
            *token = 15u << 4;
            vac::u32 len = litLen - 15u;
            if (len < 255u) {
                *op++ = static_cast<vac::u8>(len);
            } else {
                const vac::u32 blocks = len / 255u;
                memset(op, 255, blocks);
                op += blocks;
                *op++ = static_cast<vac::u8>(len % 255u);
            }
        } else {
            *token = static_cast<vac::u8>(litLen << 4);
        }
        memcpy(op, const_cast<vac::u8*>(anchor), litLen);
        op += litLen;
    }

    return static_cast<int>(op - dst);
}
// clang-format on
