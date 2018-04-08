#ifndef BITCOINX_CONTRACT_CONTRACTUTIL_H
#define BITCOINX_CONTRACT_CONTRACTUTIL_H

#include "uint256.h"
#include <libdevcrypto/Common.h>

class ContractUtil
{
public:
    static dev::Address createContractAddr(const uint256& txHash, uint32_t outIdx);
};

#endif // BITCOINX_CONTRACT_CONTRACTUTIL_H