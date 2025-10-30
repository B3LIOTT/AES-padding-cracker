#include <vector>
#include <string>
#include <functional>

#include "include/target.h"
#include "include/utils.h"


std::string Target::url;
std::string Target::method;
unsigned int Target::port;
std::string Target::data;
std::string Target::format;
std::string Target::errMsg;
unsigned int Target::blockSize;
std::function<std::vector<unsigned int>(std::string&)> Target::cypherToBytes;
std::function<std::string(std::vector<unsigned int>&)> Target::bytesToCypher;

const std::string& Target::getUrl() {
    return url;
}

const std::string& Target::getMethod() {
    return method;
}

const unsigned int& Target::getPort() {
    return port;
}

const std::string& Target::getData() {
    return data;
}

const std::string& Target::getFormat() {
    return format;
}

const std::string& Target::getErrMsg() {
    return errMsg;
}

const unsigned int& Target::getBlockSize() {
    return blockSize;
}

const std::string Target::getPayload(std::string& cypher) {
    if (method == GET) {
        return url+'?'+data+cypher;
    }

    if (method == COOKIES) {
        return data+cypher;
    }

    // if (method == POST) {
        unsigned int pos = data.find(POST_R);
        if (pos != std::string::npos) { // found
            data.replace(pos, 1, cypher);
        }
        return data;
    //}
}

const std::vector<unsigned int> Target::getBytes(std::string& cypher) {
    return cypherToBytes(cypher);
}

const std::string Target::getCypher(std::vector<unsigned int>& bytes) {
    return bytesToCypher(bytes);
}



void Target::initialize(const std::string& defaultUrl, 
                        const std::string& defaultMethod, 
                        const unsigned int& defaultPort,
                        const std::string& defaultData,
                        const std::string& defaultFormat,
                        const std::string& defaultErrMsg,
                        const unsigned int& defaultBlockSize) {
    url = defaultUrl;
    method = defaultMethod;
    port = defaultPort;
    data = defaultData;
    format = defaultFormat;
    errMsg = defaultErrMsg;
    blockSize = defaultBlockSize;

    if (Target::getFormat() == HEX) {
        bytesToCypher = BytesToHexString;
        cypherToBytes = HexStringToBytes;
    }
    else {
        bytesToCypher = BytesToBase64;
        cypherToBytes = Base64ToBytes;
    }
    
}