#include <string>

#include "include/target.h"


std::string Target::url;
std::string Target::method;
std::string Target::data;
std::string Target::errMsg;
unsigned int Target::blockSize;

const std::string& Target::getUrl() {
    return url;
}

const std::string& Target::getMethod() {
    return method;
}

const std::string& Target::getData() {
    return data;
}

const std::string& Target::getErrMsg() {
    return errMsg;
}

const unsigned int& Target::getBlockSize() {
    return blockSize;
}

const std::string Target::getPayload(std::string& cypher) {
    return url+'?'+data+cypher;
}


void Target::initialize(const std::string& defaultUrl, 
                              const std::string& defaultMethod, 
                              const std::string& defaultData,
                              const std::string& defaultErrMsg,
                              const unsigned int& defaultBlockSize) {
    url = defaultUrl;
    method = defaultMethod;
    data = defaultData;
    errMsg = defaultErrMsg;
    blockSize = defaultBlockSize;
}