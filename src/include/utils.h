#pragma once

#include <string>
#include <vector> 


#define BASE_64 "base64"
#define HEX "hex"

const std::string base64_chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";



// forward struct
struct CypherData;


// Arguments parsing
struct Args {
    std::string url;
    std::string method;
    unsigned int port;
    std::string data;
    std::string cypher;
    std::string format;
    unsigned int blockSize;
    std::string paddingError;
};

Args getArgs(int argc, char** argv);


void saveResult(const std::vector<CypherData>& data, const std::string& filename);
std::vector<CypherData> loadResult(const std::string& filename, const unsigned int& nBlocks);


// Data manipulation
std::string IntToHex(unsigned int& val);

unsigned int HexToInt(const std::string& hex);

std::vector<unsigned int> HexStringToBytes(const std::string& hex);

std::string BytesToHexString(const std::vector<unsigned int>& bytes);

std::string BytesToBase64(const std::vector<unsigned int>& bytes);

std::vector<unsigned int> Base64ToBytes(const std::string& b64);

std::string base64ToString(const std::string& base64_input);

std::string stringToBase64(const std::string& input);
