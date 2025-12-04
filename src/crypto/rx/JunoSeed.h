/* XMRig
 * Copyright (c) 2018-2021 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2021 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef XMRIG_JUNOSEED_H
#define XMRIG_JUNOSEED_H


#include <cstdint>


namespace xmrig {


class JunoSeed
{
public:
    // Juno Cash epoch constants
    static constexpr uint64_t EPOCH_LENGTH = 2048;  // Power of 2 for efficient masking
    static constexpr uint64_t SEED_LAG = 96;        // Blocks before epoch that seed is taken from

    // Calculate the block height that provides the seed for a given block height
    // Returns 0 for genesis epoch (blocks 0 through EPOCH_LENGTH + SEED_LAG)
    static uint64_t seedHeight(uint64_t blockHeight);

    // Get the epoch number for a given block height
    static uint64_t epoch(uint64_t blockHeight);

    // Check if mining at newHeight would require a different seed than currentHeight
    static bool needsSeedUpdate(uint64_t currentHeight, uint64_t newHeight);

    // Check if two heights are in the same epoch
    static bool sameEpoch(uint64_t height1, uint64_t height2);
};


} /* namespace xmrig */


#endif /* XMRIG_JUNOSEED_H */
