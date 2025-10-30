#pragma once

#include <string>
#include <vector>

// forward struct
struct CypherData;

// Blocks manipulation
std::vector<std::vector<unsigned int>> GetBlocks(std::string& cypherText);

std::string BuildCipherFromPlain(
    std::string& plainText, 
    std::vector<CypherData>& cypherDataList, 
    std::vector<unsigned int>& lastBlock,
    unsigned int& nBlocksNeeded, 
    unsigned int& plainSize
);

std::string BlocksToCypher(
    std::vector<std::vector<unsigned int>>& blocks, 
    const unsigned int& nBlocks,
    std::vector<unsigned int>& newBlock,
    unsigned int& k,
    const unsigned int& size
);

