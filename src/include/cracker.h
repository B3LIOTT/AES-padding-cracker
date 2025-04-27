#pragma once

#include <string>
#include <vector> 
#include <curl/curl.h>


struct CypherData {
    std::vector<unsigned int> Pn;
    std::vector<unsigned int> Dn;
};


bool PaddingError(std::string& response);


void Guess(
    const std::string& hexC, 
    const std::string& hexX, 
    const unsigned int& pad,
    CypherData& cypherData
);


CypherData Fuzz(
    CURL* curl,
    std::vector<std::string>& blocks, 
    unsigned int k
);

