// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Check if we're at or past the per-block difficulty activation height
    bool fPerBlockDifficulty = (pindexLast->nHeight + 1) >= params.nPerBlockDifficultyActivationHeight;
    
    if (fPerBlockDifficulty) {
        // New per-block difficulty adjustment algorithm
        return GetNextWorkRequiredPerBlock(pindexLast, pblock, params);
    }

    // Legacy difficulty adjustment logic (pre-softfork)
    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Aegisum: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int GetNextWorkRequiredPerBlock(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block or first block after activation
    if (pindexLast->pprev == nullptr || pindexLast->nHeight + 1 == params.nPerBlockDifficultyActivationHeight) {
        return pindexLast->nBits;
    }

    // Special difficulty rule for testnet:
    // If the new block's timestamp is more than 2 * target spacing
    // then allow mining of a min-difficulty block.
    if (params.fPowAllowMinDifficultyBlocks) {
        if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
            return nProofOfWorkLimit;
    }

    // Calculate the time difference between the last block and the previous block
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexLast->pprev->GetBlockTime();
    
    // Prevent negative time (should not happen in practice, but safety first)
    if (nActualTimespan < 0) {
        nActualTimespan = params.nPowTargetSpacing;
    }

    // Apply per-block difficulty adjustment limits
    // Max 10% increase in difficulty (0.9x time = 1.111x difficulty)
    // Max 20% decrease in difficulty (1.2x time = 0.833x difficulty)
    int64_t nMinTimespan = (params.nPowTargetSpacing * 9) / 10;  // 90% of target = max difficulty increase
    int64_t nMaxTimespan = (params.nPowTargetSpacing * 12) / 10; // 120% of target = max difficulty decrease

    if (nActualTimespan < nMinTimespan)
        nActualTimespan = nMinTimespan;
    if (nActualTimespan > nMaxTimespan)
        nActualTimespan = nMaxTimespan;

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    
    // Aegisum: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetSpacing;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    
    // Check if we're at or past the activation height
    bool fNewRules = pindexLast->nHeight >= params.nDifficultyChangeActivationHeight;
    
    if (fNewRules) {
        // New rules: limit upward difficulty change to 1.5x (instead of 4x)
        if (nActualTimespan < (params.nPowTargetTimespan * 2) / 3)
            nActualTimespan = (params.nPowTargetTimespan * 2) / 3;
            
        // New rules: allow downward difficulty change up to 6x (instead of 4x)
        if (nActualTimespan > params.nPowTargetTimespan * 6)
            nActualTimespan = params.nPowTargetTimespan * 6;
    } else {
        // Old rules: limit upward difficulty change to 4x
        if (nActualTimespan < params.nPowTargetTimespan/4)
            nActualTimespan = params.nPowTargetTimespan/4;
            
        // Old rules: limit downward difficulty change to 4x
        if (nActualTimespan > params.nPowTargetTimespan*4)
            nActualTimespan = params.nPowTargetTimespan*4;
    }

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Aegisum: intermediate uint256 can overflow by 1 bit
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    bool fShift = bnNew.bits() > bnPowLimit.bits() - 1;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
