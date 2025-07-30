#pragma once

#include <sys/socket.h>
#include <curl/curl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <string>


CURL* CurlInit();

void CurlCleanup(CURL* curl);

static size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata);

std::string GetRequest(CURL* curl, const std::string& fullUrl);

//std::string PostRequest(const std::string& payload);

std::string CookiesRequest(CURL* curl, const std::string& url, const std::string& cookies);


// SOCKET -------------------

class SocketClient {
private:
    std::string url;
    unsigned int port;
    int sockfd;

public:
    SocketClient(const std::string& url, const unsigned int& port);

    ~SocketClient();

    std::string socketRequest(const std::string& payload);
};

