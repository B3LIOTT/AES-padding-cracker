#pragma once

#include <string>
#include <vector> 


// forward struct
struct CypherData;


// Arguments parsing
struct Args {
    std::string url;
    std::string method;
    std::string data;
    std::string cypher;
    unsigned int blockSize;
    std::string paddingError;
};

Args getArgs(int argc, char** argv);

// Hex manipulation
std::string IntToHex(unsigned int& val);

unsigned int HexToInt(const std::string& hex);


// Blocks manipulation
std::string BlocksToCypher(std::vector<std::string>& blocks, const unsigned int& nBlocks);

std::vector<std::string> GetBlocks(std::string& cypherText);

void ModifyBlock(
    std::string& block, 
    std::string val, 
    unsigned int& ind
);

std::vector<std::string> BuildBlocks(std::string& plainText, std::vector<CypherData>& cypherDataList, unsigned int& nBlocksNeeded, unsigned int& plainSize);

std::string BlocksToCypher(
    std::vector<std::string>& blocks, 
    const unsigned int& nBlocks,
    std::string& newBlock,
    unsigned int& k,
    const unsigned int& size
);

std::string GetVal(std::string& str, unsigned int& ind);

