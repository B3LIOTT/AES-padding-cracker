#pragma once

#include <string>
#include <vector> 
#include <curl/curl.h>


// forward struct
struct CypherData;


bool PaddingError(std::string& response);


void Guess(
    const std::string& hexC, 
    const unsigned int& X, 
    const unsigned int& pad,
    CypherData& cypherData
);


CypherData Fuzz(
    std::function<std::string(std::string&)> request, 
    std::vector<std::string>& blocks, 
    unsigned int k
);

