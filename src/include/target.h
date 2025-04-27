#pragma once

#include <string>


class Target {
    public:
        Target() = delete;
        
        // Getters
        static const std::string& getUrl();
        static const std::string& getMethod();
        static const std::string& getData();
        static const std::string& getErrMsg();
        static const unsigned int& getBlockSize();

        static const std::string getPayload(std::string& cypher);
        
        static void initialize(const std::string& defaultUrl, 
                              const std::string& defaultMethod, 
                              const std::string& defaultGetParam,
                              const std::string& defaultErrMsg,
                              const unsigned int& defaultBlockSize);
        
    private:
        static std::string url;
        static std::string method;
        static std::string data;
        static std::string errMsg;
        static unsigned int blockSize;
    };