#pragma once

#include <string>
#include <vector> 
#include <curl/curl.h>


// forward struct
struct CypherData;


bool PaddingError(std::string& response);


void Guess(
    const unsigned int& C, 
    const unsigned int& X, 
    const unsigned int& pad,
    CypherData& cypherData
);


CypherData Fuzz(
    std::function<std::string(std::string&)> request, 
    std::vector<std::vector<unsigned int>>& blocks, 
    unsigned int k,
    std::function<std::string(const std::vector<unsigned int>&)> convert
);

