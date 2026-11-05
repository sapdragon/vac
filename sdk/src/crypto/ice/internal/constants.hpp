#pragma once

#include "core/types.hpp"

namespace vac::crypto::ice::detail
{

inline constexpr u32 k_rgrgunSxor[4][4] = {
    { 0x83, 0x85, 0x9B, 0xCD },
    { 0xCC, 0xA7, 0xAD, 0x41 },
    { 0x4B, 0x2E, 0xD4, 0x33 },
    { 0xEA, 0xCB, 0x2E, 0x04 },
};

inline constexpr u32 k_rgrgunSmod[4][4] = {
    { 333, 313, 505, 369 },
    { 379, 375, 319, 391 },
    { 361, 445, 451, 397 },
    { 397, 425, 395, 505 },
};

inline constexpr u32 k_rgunPbox[32] = {
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
};

inline constexpr u32 k_rgunKeyRot[16] = {
    0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2,
};

} // namespace vac::crypto::ice::detail
