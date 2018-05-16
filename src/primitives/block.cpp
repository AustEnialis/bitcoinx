// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "hash.h"
#include "hash_blake2.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"
#include "versionbits.h"



uint256 CBaseBlockHeader::GetPoWHash() const
{
    if (CheckBCXVersion())
    {
        return Blake2::SerializeHash(*this);    
    }
    return SerializeHash(*this); 
}

bool CBaseBlockHeader::CheckBCXVersion(int version)
{
    static const int BCX_BIT = 24;
    return (version & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS
        && (version >> BCX_BIT) == ((VERSIONBITS_TOP_BITS | VERSIONBITS_BCX_MASK) >> BCX_BIT);
}

bool CBaseBlockHeader::CheckBCXContractVersion(int version)
{
    if (CheckBCXVersion(version)) {
        return (version & VERSIONBITS_BCX_CONTRACT_BITS) != 0;
    }
    return false;
}

uint256 CBlockHeader::GetHash() const
{
    if (CheckBCXVersion())
    {
        return Blake2::SerializeHash(*this);    
    }
    return SerializeHash(*this);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, powHash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        GetPoWHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        hashStateRoot.ToString(),
        hashUTXORoot.ToString(),
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
