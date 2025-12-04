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


#include "crypto/rx/JunoSeed.h"


namespace xmrig {


uint64_t JunoSeed::epoch(uint64_t blockHeight)
{
    // Epoch 0: blocks 0 to (EPOCH_LENGTH + SEED_LAG - 1)
    // Epoch 1: blocks (EPOCH_LENGTH + SEED_LAG) to (2 * EPOCH_LENGTH + SEED_LAG - 1)
    // etc.

    if (blockHeight < EPOCH_LENGTH + SEED_LAG) {
        return 0;
    }

    return (blockHeight - SEED_LAG) / EPOCH_LENGTH;
}


uint64_t JunoSeed::seedHeight(uint64_t blockHeight)
{
    // For genesis epoch (epoch 0), use seed height 0 (which means use genesis seed)
    if (blockHeight <= EPOCH_LENGTH + SEED_LAG) {
        return 0;
    }

    // Calculate the epoch boundary
    // The seed is taken from SEED_LAG blocks before the epoch start
    // Using bitmask for efficient calculation since EPOCH_LENGTH is power of 2

    // epoch_start = ((blockHeight - SEED_LAG - 1) / EPOCH_LENGTH) * EPOCH_LENGTH
    // seed_height = epoch_start

    return (blockHeight - SEED_LAG - 1) & ~(EPOCH_LENGTH - 1);
}


bool JunoSeed::needsSeedUpdate(uint64_t currentHeight, uint64_t newHeight)
{
    return epoch(currentHeight) != epoch(newHeight);
}


bool JunoSeed::sameEpoch(uint64_t height1, uint64_t height2)
{
    return epoch(height1) == epoch(height2);
}


} /* namespace xmrig */
