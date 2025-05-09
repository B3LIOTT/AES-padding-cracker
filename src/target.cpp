#include <string>

#include "include/target.h"


std::string Target::url;
std::string Target::method;
unsigned int Target::port;
std::string Target::data;
std::string Target::errMsg;
unsigned int Target::blockSize;

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
                              const unsigned int& defaultPort,
                              const std::string& defaultData,
                              const std::string& defaultErrMsg,
                              const unsigned int& defaultBlockSize) {
    url = defaultUrl;
    method = defaultMethod;
    port = defaultPort;
    data = defaultData;
    errMsg = defaultErrMsg;
    blockSize = defaultBlockSize;
}