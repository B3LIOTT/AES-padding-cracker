#pragma once

#include <string>
#include <vector>

// forward struct
struct CypherData;

// Blocks manipulation
std::vector<std::vector<unsigned int>> GetBlocks(std::string& cypherText);

void BuildBlocks(
    std::string& plainText, 
    std::vector<CypherData>& cypherDataList, 
    std::vector<std::string>& newBlocks,
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

