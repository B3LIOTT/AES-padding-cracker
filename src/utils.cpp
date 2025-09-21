#include <stdexcept> 
#include <iostream>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <string>


#include "cxxopts/cxxopts.hpp"
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
            ("f,format", "Cypher text format (base64, hex)", cxxopts::value<std::string>())
            ("b,block-size", "Block size (8,16,32,64)", cxxopts::value<unsigned int>())
            ("e,padding-error", "Padding error text", cxxopts::value<std::string>())
            ("h,help", "Print usage");

        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            Log::print(options.help());
            exit(0);
        }

        // verify args
        if (!result.count("url") || !result.count("method") || !result.count("cypher") || !result.count("format") ||
            !result.count("block-size") || !result.count("padding-error")) {
            throw std::runtime_error("Missing required arguments, use -h option to see details");
        }

        args.blockSize = result["block-size"].as<unsigned int>();
        if (args.blockSize != 8 && args.blockSize != 16 && args.blockSize != 32 && args.blockSize != 64) {
            throw std::runtime_error("Block size must be 8,16,32 or 64");
        }

        args.cypher = result["cypher"].as<std::string>();
        args.format = result["format"].as<std::string>();
        if (args.format != "base64" && args.format != "hex") {
            throw std::runtime_error("Format must be base64 or hex");
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

std::vector<unsigned int> HexStringToBytes(const std::string& hex) {
    std::vector<unsigned int> bytes;
    size_t len = hex.length();

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


// Base64 manipulation
std::string BytesToHexString(const std::vector<unsigned int>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::uppercase;

    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

std::string BytesToBase64(const std::vector<unsigned int>& bytes) {
    std::string encoded;
    int val = 0;
    int valb = -6;
    for (unsigned int c : bytes) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
        encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4)
        encoded.push_back('=');
    return encoded;
}

std::vector<unsigned int> Base64ToBytes(const std::string& b64) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++)
        T[base64_chars[i]] = i;

    Log::print(std::to_string(T[0]));

    std::vector<unsigned int> decoded;
    int val = 0;
    int valb = -8;
    for (unsigned int c : b64) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return decoded;
}

