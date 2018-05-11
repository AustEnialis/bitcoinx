#include "base58.h"
#include "config.h"
#include "consensus/validation.h"
#include "contractexecutor.h"
#include "contractutil.h"
#include "core_io.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "timedata.h"
#include "univalue.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validation.h"
#include "vmlog.h"
#include "wallet/coincontrol.h"
#include "wallet/rpcwallet.h"
#include "wallet/wallet.h"


extern std::unique_ptr<CConnman> g_connman;

UniValue createcontract(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    const uint64_t blockGasLimit = DEFAULT_BLOCK_GAS_LIMIT;
    CAmount nGasPrice = DEFAULT_GAS_PRICE;

    if (request.fHelp || request.params.size() < 1 || request.params.size() > 6)
        throw std::runtime_error(
            "createcontract \"bytecode\" (gaslimit gasprice \"senderaddress\" broadcast)"
            "\nCreate a contract with bytcode.\n" +
            HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"bytecode\"  (string, required) contract bytcode.\n"
            "2. gasLimit  (numeric or string, optional) gasLimit, default: " +
            i64tostr(DEFAULT_GAS_LIMIT_OP_CREATE) + ", max: " + i64tostr(blockGasLimit) + "\n"
                                                                                          "3. gasPrice  (numeric or string, optional) gasPrice price per gas unit, default: " +
            FormatMoney(nGasPrice) + ", min:" + FormatMoney(MIN_GAS_PRICE) + "\n"
                                                                             "4. \"senderaddress\" (string, optional) The bitcoinx address that will be used to create the contract.\n"
                                                                             "5. \"broadcast\" (bool, optional, default=true) Whether to broadcast the transaction or not.\n"
                                                                             "6. \"changeToSender\" (bool, optional, default=true) Return the change to the sender.\n"
                                                                             "\nResult:\n"
                                                                             "[\n"
                                                                             "  {\n"
                                                                             "    \"txid\" : (string) The transaction id.\n"
                                                                             "    \"sender\" : (string) " +
            CURRENCY_UNIT + " address of the sender.\n"
                            "    \"hash160\" : (string) ripemd-160 hash of the sender.\n"
                            "    \"address\" : (string) expected contract address.\n"
                            "  }\n"
                            "]\n"
                            "\nExamples:\n" +
            HelpExampleCli("createcontract", "\"60606040525b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff02191690836c010000000000000000000000009081020402179055506103786001600050819055505b600c80605b6000396000f360606040526008565b600256\"") + HelpExampleCli("createcontract", "\"60606040525b33600060006101000a81548173ffffffffffffffffffffffffffffffffffffffff02191690836c010000000000000000000000009081020402179055506103786001600050819055505b600c80605b6000396000f360606040526008565b600256\" 6000000 " + FormatMoney(MIN_GAS_PRICE) + " \"QM72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" true"));


    const std::string& bytecode = request.params[0].get_str();
    if (bytecode.size() % 2 != 0 || !CheckHex(bytecode))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    uint64_t nGasLimit = DEFAULT_GAS_LIMIT_OP_CREATE;
    if (request.params.size() > 1) {
        nGasLimit = request.params[1].get_int64();
        if (nGasLimit > blockGasLimit)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Maximum is: " + i64tostr(blockGasLimit) + ")");
        if (nGasLimit < MINIMUM_GAS_LIMIT)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Minimum is: " + i64tostr(MINIMUM_GAS_LIMIT) + ")");
    }

    if (request.params.size() > 2) {
        UniValue uGasPrice = request.params[2];
        if (!ParseMoney(uGasPrice.getValStr(), nGasPrice)) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice");
        }
        CAmount maxRpcGasPrice = gArgs.GetArg("-rpcmaxgasprice", MAX_RPC_GAS_PRICE);
        if (nGasPrice > (int64_t)maxRpcGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice, Maximum allowed in RPC calls is: " + FormatMoney(maxRpcGasPrice) + " (use -rpcmaxgasprice to change it)");
        if (nGasPrice < (int64_t)MIN_GAS_PRICE)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice (Minimum is: " + FormatMoney(MIN_GAS_PRICE) + ")");
    }

    bool fHasSender = false;
    CBitcoinAddress senderAddress;
    if (request.params.size() > 3) {
        senderAddress.SetString(request.params[3].get_str());
        if (!senderAddress.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid bitcoinx address to send from");
        else
            fHasSender = true;
    }

    bool fBroadcast = true;
    if (request.params.size() > 4) {
        fBroadcast = request.params[4].get_bool();
    }

    bool fChangeToSender = true;
    if (request.params.size() > 5) {
        fChangeToSender = request.params[5].get_bool();
    }

    CCoinControl coinControl;

    if (fHasSender) {
        //find a UTXO with sender address

        UniValue results(UniValue::VARR);
        std::vector<COutput> vecOutputs;

        coinControl.fAllowOtherInputs = true;

        assert(pwallet != NULL);
        pwallet->AvailableCoins(vecOutputs, false, NULL, true);

        for (const COutput& out : vecOutputs) {
            CTxDestination address;
            const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, address);

            CBitcoinAddress destAdress(address);

            if (!fValidAddress || senderAddress.Get() != destAdress.Get())
                continue;

            coinControl.Select(COutPoint(out.tx->GetHash(), out.i));

            break;
        }

        if (!coinControl.HasSelected()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Sender address does not have any unspent outputs");
        }
        if (fChangeToSender) {
            coinControl.destChange = senderAddress.Get();
        }
    }
    EnsureWalletIsUnlocked(pwallet);

    CWalletTx wtx;
    wtx.nTimeSmart = GetAdjustedTime();

    const CAmount nGasFee = nGasPrice * nGasLimit / BCX_2_GAS_RATE;
    const CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nGasFee <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nGasFee > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Build OP_EXEC script
    CScript scriptPubKey = CScript() << CScriptNum(EthTxVersion::GetDefault().ToRaw()) << CScriptNum(nGasLimit) << CScriptNum(nGasPrice) << ParseHex(bytecode) << OP_CREATECONTRACT;

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, 0, false};
    vecSend.push_back(recipient);

    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coinControl, true, nGasFee, fHasSender)) {
        if (nFeeRequired > pwallet->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    CTxDestination txSenderDest;
    ExtractDestination(pwallet->mapWallet[wtx.tx->vin[0].prevout.hash].tx->vout[wtx.tx->vin[0].prevout.n].scriptPubKey, txSenderDest);

    if (fHasSender && !(senderAddress.Get() == txSenderDest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender could not be set, transaction was not committed!");
    }

    UniValue result(UniValue::VOBJ);
    if (fBroadcast) {
        CValidationState state;
        if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of the wallet and coins were spent in the copy but not marked as spent here.");

        const std::string& txId = wtx.GetHash().GetHex();
        result.push_back(Pair("txid", txId));

        CBitcoinAddress txSenderAdress(txSenderDest);
        CKeyID keyid;
        txSenderAdress.GetKeyID(keyid);

        result.push_back(Pair("sender", txSenderAdress.ToString()));
        result.push_back(Pair("hash160", HexStr(valtype(keyid.begin(), keyid.end()))));

        uint32_t outIdx = 0;
        for (const CTxOut& txout : wtx.tx->vout) {
            if (txout.scriptPubKey.HasCreateContractOp()) {
                const dev::Address& contractAddr = ContractUtil::createContractAddr(wtx.GetHash(), outIdx);
                result.push_back(Pair("address", HexStr(contractAddr.asBytes())));
                break;
            }
            outIdx++;
        }
    } else {
        const std::string& strHex = EncodeHexTx(*wtx.tx, RPCSerializationFlags());
        result.push_back(Pair("raw transaction", strHex));
    }
    return result;
}

static UniValue executionResultToJSON(const dev::eth::ExecutionResult& exRes)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("gasUsed", CAmount(exRes.gasUsed)));
    std::stringstream ss;
    ss << exRes.excepted;
    result.push_back(Pair("excepted", ss.str()));
    result.push_back(Pair("newAddress", exRes.newAddress.hex()));
    result.push_back(Pair("output", HexStr(exRes.output)));
    result.push_back(Pair("codeDeposit", static_cast<int32_t>(exRes.codeDeposit)));
    result.push_back(Pair("gasRefunded", CAmount(exRes.gasRefunded)));
    result.push_back(Pair("depositSize", static_cast<int32_t>(exRes.depositSize)));
    result.push_back(Pair("gasForDeposit", CAmount(exRes.gasForDeposit)));
    return result;
}

static UniValue transactionReceiptToJSON(const dev::eth::TransactionReceipt& txRec)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("stateRoot", txRec.stateRoot().hex()));
    result.push_back(Pair("gasUsed", CAmount(txRec.gasUsed())));
    result.push_back(Pair("bloom", txRec.bloom().hex()));
    UniValue logEntries(UniValue::VARR);
    dev::eth::LogEntries logs = txRec.log();
    for (dev::eth::LogEntry log : logs) {
        UniValue logEntrie(UniValue::VOBJ);
        logEntrie.push_back(Pair("address", log.address.hex()));
        UniValue topics(UniValue::VARR);
        for (dev::h256 l : log.topics) {
            topics.push_back(l.hex());
        }
        logEntrie.push_back(Pair("topics", topics));
        logEntrie.push_back(Pair("data", HexStr(log.data)));
        logEntries.push_back(logEntrie);
    }
    result.push_back(Pair("log", logEntries));
    return result;
}

UniValue callcontract(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2)
        throw std::runtime_error(
            "callcontract \"address\" \"data\" ( address )\n"
            "\nArgument:\n"
            "1. \"address\"          (string, required) The account address\n"
            "2. \"data\"             (string, required) The data hex string\n"
            "3. address              (string, optional) The sender address hex string\n"
            "4. gasLimit             (string, optional) The gas limit for executing the contract\n");

    LOCK(cs_main);

    const std::string& strAddr = request.params[0].get_str();
    const std::string& data = request.params[1].get_str();

    if (data.size() % 2 != 0 || !CheckHex(data))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    if (strAddr.size() != 40 || !CheckHex(strAddr))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect address");

    dev::Address addrAccount(strAddr);
    if (!EthState::Instance()->addressInUse(addrAccount))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address does not exist");

    dev::Address senderAddress;
    if (request.params.size() == 3) {
        CBitcoinAddress bcxSender(request.params[2].get_str());
        if (bcxSender.IsValid()) {
            CKeyID keyid;
            bcxSender.GetKeyID(keyid);
            senderAddress = dev::Address(HexStr(valtype(keyid.begin(), keyid.end())));
        } else {
            senderAddress = dev::Address(request.params[2].get_str());
        }
    }
    uint64_t gasLimit = 0;
    if (request.params.size() == 4) {
        gasLimit = request.params[3].get_int();
    }

    const std::vector<EthExecutionResult>& execResults = ContractExecutor::Call(addrAccount, ParseHex(data), senderAddress, gasLimit);
    if (fRecordLogOpcodes) {
        VMLog::Write(execResults);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", strAddr));
    result.push_back(Pair("executionResult", executionResultToJSON(execResults[0].execRes)));
    result.push_back(Pair("transactionReceipt", transactionReceiptToJSON(execResults[0].txRec)));

    return result;
}

UniValue sendtocontract(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    CAmount nGasPrice = DEFAULT_GAS_PRICE;
    const uint64_t blockGasLimit = DEFAULT_BLOCK_GAS_LIMIT;

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 8)
        throw std::runtime_error(
            "sendtocontract \"contractaddress\" \"data\" (amount gaslimit gasprice senderaddress broadcast)"
            "\nSend funds and data to a contract.\n" +
            HelpRequiringPassphrase(pwallet) +
            "\nArguments:\n"
            "1. \"contractaddress\" (string, required) The contract address that will receive the funds and data.\n"
            "2. \"datahex\"  (string, required) data to send.\n"
            "3. \"amount\"      (numeric or string, optional) The amount in " +
            CURRENCY_UNIT + " to send. eg 0.1, default: 0\n"
                            "4. gasLimit  (numeric or string, optional) gasLimit, default: " +
            i64tostr(DEFAULT_GAS_LIMIT_OP_SEND) + ", max: " + i64tostr(blockGasLimit) + "\n"
                                                                                        "5. gasPrice  (numeric or string, optional) gasPrice price per gas unit, default: " +
            FormatMoney(nGasPrice) + ", min:" + FormatMoney(MIN_GAS_PRICE) + "\n"
                                                                             "6. \"senderaddress\" (string, optional) The bitcoinx address that will be used as sender.\n"
                                                                             "7. \"broadcast\" (bool, optional, default=true) Whether to broadcast the transaction or not.\n"
                                                                             "8. \"changeToSender\" (bool, optional, default=true) Return the change to the sender.\n"
                                                                             "\nResult:\n"
                                                                             "[\n"
                                                                             "  {\n"
                                                                             "    \"txid\" : (string) The transaction id.\n"
                                                                             "    \"sender\" : (string) " +
            CURRENCY_UNIT + " address of the sender.\n"
                            "    \"hash160\" : (string) ripemd-160 hash of the sender.\n"
                            "  }\n"
                            "]\n"
                            "\nExamples:\n" +
            HelpExampleCli("sendtocontract", "\"c6ca2697719d00446d4ea51f6fac8fd1e9310214\" \"54f6127f\"") + HelpExampleCli("sendtocontract", "\"c6ca2697719d00446d4ea51f6fac8fd1e9310214\" \"54f6127f\" 12.0015 6000000 " + FormatMoney(MIN_GAS_PRICE) + " \"QM72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\""));


    const std::string& contractaddress = request.params[0].get_str();
    if (contractaddress.size() != 40 || !CheckHex(contractaddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Incorrect contract address");

    dev::Address addrAccount(contractaddress);
    if (!EthState::Instance()->addressInUse(addrAccount))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "contract address does not exist");

    const std::string& datahex = request.params[1].get_str();
    if (datahex.size() % 2 != 0 || !CheckHex(datahex))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid data (data not hex)");

    CAmount nAmount = 0;
    if (request.params.size() > 2) {
        nAmount = AmountFromValue(request.params[2]);
        if (nAmount < 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
    }

    uint64_t nGasLimit = DEFAULT_GAS_LIMIT_OP_SEND;
    if (request.params.size() > 3) {
        nGasLimit = request.params[3].get_int64();
        if (nGasLimit > blockGasLimit)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Maximum is: " + i64tostr(blockGasLimit) + ")");
        if (nGasLimit < MINIMUM_GAS_LIMIT)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasLimit (Minimum is: " + i64tostr(MINIMUM_GAS_LIMIT) + ")");
    }

    if (request.params.size() > 4) {
        UniValue uGasPrice = request.params[4];
        if (!ParseMoney(uGasPrice.getValStr(), nGasPrice)) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice");
        }
        CAmount maxRpcGasPrice = gArgs.GetArg("-rpcmaxgasprice", MAX_RPC_GAS_PRICE);
        if (nGasPrice > (int64_t)maxRpcGasPrice)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice, Maximum allowed in RPC calls is: " + FormatMoney(maxRpcGasPrice) + " (use -rpcmaxgasprice to change it)");
        if (nGasPrice < (int64_t)MIN_GAS_PRICE)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid value for gasPrice (Minimum is: " + FormatMoney(MIN_GAS_PRICE) + ")");
    }

    bool fHasSender = false;
    CBitcoinAddress senderAddress;
    if (request.params.size() > 5) {
        senderAddress.SetString(request.params[5].get_str());
        if (!senderAddress.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid bitcoinx address to send from");
        else
            fHasSender = true;
    }

    bool fBroadcast = true;
    if (request.params.size() > 6) {
        fBroadcast = request.params[6].get_bool();
    }

    bool fChangeToSender = true;
    if (request.params.size() > 7) {
        fChangeToSender = request.params[7].get_bool();
    }

    CCoinControl coinControl;

    if (fHasSender) {
        UniValue results(UniValue::VARR);
        std::vector<COutput> vecOutputs;

        coinControl.fAllowOtherInputs = true;

        assert(pwallet != NULL);
        pwallet->AvailableCoins(vecOutputs, false, NULL, true);

        for (const COutput& out : vecOutputs) {
            CTxDestination address;
            const CScript& scriptPubKey = out.tx->tx->vout[out.i].scriptPubKey;
            bool fValidAddress = ExtractDestination(scriptPubKey, address);

            CBitcoinAddress destAdress(address);

            if (!fValidAddress || senderAddress.Get() != destAdress.Get())
                continue;

            coinControl.Select(COutPoint(out.tx->GetHash(), out.i));

            break;
        }

        if (!coinControl.HasSelected()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Sender address does not have any unspent outputs");
        }
        if (fChangeToSender) {
            coinControl.destChange = senderAddress.Get();
        }
    }

    EnsureWalletIsUnlocked(pwallet);

    CWalletTx wtx;
    wtx.nTimeSmart = GetAdjustedTime();

    const CAmount nGasFee = nGasPrice * nGasLimit / BCX_2_GAS_RATE;
    const CAmount curBalance = pwallet->GetBalance();

    // Check amount
    if (nGasFee <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount for gas fee");

    if (nAmount + nGasFee > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Build OP_EXEC_ASSIGN script
    CScript scriptPubKey = CScript() << CScriptNum(EthTxVersion::GetDefault().ToRaw()) << CScriptNum(nGasLimit) << CScriptNum(nGasPrice) << ParseHex(datahex) << ParseHex(contractaddress) << OP_SENDTOCONTRACT;

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nAmount, false};
    vecSend.push_back(recipient);

    if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, coinControl, true, nGasFee, fHasSender)) {
        if (nFeeRequired > pwallet->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }

    CTxDestination txSenderDest;
    ExtractDestination(pwallet->mapWallet[wtx.tx->vin[0].prevout.hash].tx->vout[wtx.tx->vin[0].prevout.n].scriptPubKey, txSenderDest);

    if (fHasSender && !(senderAddress.Get() == txSenderDest)) {
        throw JSONRPCError(RPC_TYPE_ERROR, "Sender could not be set, transaction was not committed!");
    }

    UniValue result(UniValue::VOBJ);

    if (fBroadcast) {
        CValidationState state;
        if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of the wallet and coins were spent in the copy but not marked as spent here.");

        const std::string& txId = wtx.GetHash().GetHex();
        result.push_back(Pair("txid", txId));

        CBitcoinAddress txSenderAdress(txSenderDest);
        CKeyID keyid;
        txSenderAdress.GetKeyID(keyid);

        result.push_back(Pair("sender", txSenderAdress.ToString()));
        result.push_back(Pair("hash160", HexStr(valtype(keyid.begin(), keyid.end()))));
    } else {
        const std::string& strHex = EncodeHexTx(*wtx.tx, RPCSerializationFlags());
        result.push_back(Pair("raw transaction", strHex));
    }

    return result;
}

UniValue listcontracts(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
                "listcontracts (start maxDisplay)\n"
                "\nArgument:\n"
                "1. start     (numeric or string, optional) The starting account index, default 1\n"
                "2. maxDisplay       (numeric or string, optional) Max accounts to list, default 20\n"
        );

    LOCK(cs_main);

    int start=1;
    if (request.params.size() > 0){
        start = request.params[0].get_int();
        if (start<= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid start, min=1");
    }

    int maxDisplay=20;
    if (request.params.size() > 1){
        maxDisplay = request.params[1].get_int();
        if (maxDisplay <= 0)
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid maxDisplay");
    }

    UniValue result(UniValue::VOBJ);

    const auto &map = EthState::Instance()->addresses();
    const int contractsCount = (int)map.size();

    if (contractsCount > 0 && start > contractsCount)
        throw JSONRPCError(RPC_TYPE_ERROR, "start greater than max index "+ itostr(contractsCount));

    const int itStartPos = std::min(start-1,contractsCount);
    int i = 0;
    for (auto it = std::next(map.begin(), itStartPos); it != map.end(); it++)
    {
        result.push_back(Pair(it->first.hex(), ValueFromAmount(CAmount(EthState::Instance()->balance(it->first) / BCX_2_GAS_RATE))));
        i++;
        if (i == maxDisplay) break;
    }

    return result;
}

UniValue gethexaddress(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
                "gethexaddress \"address\"\n"

                        "\nConverts a base58 pubkeyhash address to a hex address for use in smart contracts.\n"

                        "\nArguments:\n"
                        "1. \"address\"      (string, required) The base58 address\n"

                        "\nResult:\n"
                        "\"hexaddress\"      (string) The raw hex pubkeyhash address for use in smart contracts\n"

                        "\nExamples:\n"
                + HelpExampleCli("gethexaddress", "\"address\"")
                + HelpExampleRpc("gethexaddress", "\"address\"")
        );

    CBitcoinAddress address(request.params[0].get_str());
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid bitcoinx address");

    if(!address.IsPubKeyHash())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Only pubkeyhash addresses are supported");

    return boost::get<CKeyID>(address.Get()).GetReverseHex();
}

UniValue fromhexaddress(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 1)
        throw std::runtime_error(
                "fromhexaddress \"hexaddress\"\n"

                        "\nConverts a raw hex address to a base58 pubkeyhash address\n"

                        "\nArguments:\n"
                        "1. \"hexaddress\"      (string, required) The raw hex address\n"

                        "\nResult:\n"
                        "\"address\"      (string) The base58 pubkeyhash address\n"

                        "\nExamples:\n"
                + HelpExampleCli("fromhexaddress", "\"hexaddress\"")
                + HelpExampleRpc("fromhexaddress", "\"hexaddress\"")
        );
    if (request.params[0].get_str().size() != 40)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid pubkeyhash hex size (should be 40 hex characters)");
    CKeyID raw;
    raw.SetReverseHex(request.params[0].get_str());
    CBitcoinAddress address(raw);

    return address.ToString();
}