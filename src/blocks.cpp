#include <string>
#include <vector>
#include <stdexcept>

#include "include/common.h"
#include "include/target.h"
#include "include/log.h"


// Blocks manipulation
std::vector<std::vector<unsigned int>> GetBlocks(std::string& cypherText) {
    std::vector<std::vector<unsigned int>> blocks;
    const unsigned int blockSize = Target::getBlockSize();

    // first block of 0x00, in order to decrypt the first block
    std::vector<unsigned int> block(blockSize, 0);
    blocks.push_back(block);

    // Get cyphertext bytes
    std::vector<unsigned int> cypherBytes = Target::getBytes(cypherText);
    if (cypherBytes.size() % blockSize != 0) {
        throw std::runtime_error("Your cyphertext is not a multiple of the given block size");
    }

    unsigned int k;
    for (k=0; k<cypherBytes.size(); k+=blockSize) {
        std::vector<unsigned int> tmpBlock(cypherBytes.begin() + k, cypherBytes.begin() + k + blockSize);
        blocks.push_back(tmpBlock);
    }
    
    return blocks;
}

// TODO: change it 
/*
    recall that C1^D2 = P2
    hence if we want C1^D2 = M
    we build C1 as C1 = M^D2
    
    add padding to the desired plain text to validate the decryption
*/
std::string BuildCipherFromPlain(
    std::string& plainText, 
    std::vector<CypherData>& cypherDataList, 
    std::vector<unsigned int>& lastBlock,
    unsigned int& nBlocksNeeded, 
    unsigned int& plainSize
) {
    unsigned int blockSize = Target::getBlockSize();
    unsigned int padLen = blockSize*nBlocksNeeded - plainSize;
    unsigned int N = blockSize;
    std::vector<unsigned int> cipherBytes;

    unsigned int k;
    unsigned int j;
    unsigned int i;
    unsigned int ascii;

    for (k=0; k<nBlocksNeeded; k++) {
        // for the last block, we have to consider the case where the plain text size isn't a multiple of block size
        if (k == nBlocksNeeded-1) { 
            N = plainSize - blockSize*k;
        }
        for (i=0; i<N; i++) {
            ascii = static_cast<unsigned int>(plainText[blockSize*k+i]) ^ cypherDataList[k].Dn[i];            
            cipherBytes.push_back(ascii);
        }

        // if it is le last block, we have to pad the end of it (when the message lenght isn't a multiple of 16)
        if (k == nBlocksNeeded-1) { 
            for (j=N; j<N+padLen; j++) {
                ascii = padLen ^ cypherDataList[k].Dn[j];
                cipherBytes.push_back(ascii);
            }
        }
    }

    // append the last block
    for (i=0; i<blockSize; i++) {
        cipherBytes.push_back(lastBlock[i]);
    }

    return Target::getCypher(cipherBytes);
}


std::string BlocksToCypher(
    std::vector<std::vector<unsigned int>>& blocks, 
    const unsigned int& nBlocks,
    std::vector<unsigned int>& newBlock,
    unsigned int& k,
    const unsigned int& size
) {
    std::vector<unsigned int> cypherBytes = blocks[0];
    unsigned int i;
    for (i=0; i<nBlocks; i++) {
        if (i==k) {
            cypherBytes.insert(cypherBytes.end(), newBlock.begin(), newBlock.end());;
        } else {
            cypherBytes.insert(cypherBytes.end(), blocks[i].begin(), blocks[i].end());;
        }
    }

    return Target::getCypher(cypherBytes);
}

