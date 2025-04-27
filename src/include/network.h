#pragma once

#include <string>
#include <curl/curl.h>



CURL* CurlInit();

void CurlCleanup(CURL* curl);

static size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata);

std::string GetRequest(CURL* curl, const std::string& fullUrl);

//std::string PostRequest(const std::string& payload);


class SocketClient {
private:
    std::string url;
    int conn;

public:
    SocketClient(const std::string& serverUrl);

    ~SocketClient();

    bool connect();

    std::string socketRequest(const std::string& payload);

    bool isConnected() const;
};

