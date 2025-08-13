#include <curl/curl.h>
#include <stdexcept>
#include <netdb.h> 
#include <string>
#include <mutex>

#include "include/network.h"
#include "include/constants.h"
#include "include/log.h"


static size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}


std::string GetRequest(CURL* curl, const std::string& fullUrl) {
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, fullUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        throw std::runtime_error(curl_easy_strerror(res));
    }

    return response;
}


std::string PostRequest(CURL* curl, const std::string& url, const std::string& payload) {
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // POST
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.size());

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        throw std::runtime_error(curl_easy_strerror(res));
    }

    return response;
}



std::string CookiesRequest(CURL* curl, const std::string& url, const std::string& cookies) {
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    // COOKIES (payload)
    curl_easy_setopt(curl, CURLOPT_COOKIE, cookies);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        throw std::runtime_error(curl_easy_strerror(res));
    }

    return response;
}


CURL* CurlInit() {
    CURL* curl = curl_easy_init();
    if (!curl) {
        Log::error("Failed to initialize curl");
        exit(1);
    }

    return curl;
}


void CurlCleanup(CURL* curl) {
    curl_easy_cleanup(curl);
}


// SOCKET ----------------------------
std::mutex socket_mutex;

SocketClient::SocketClient(const std::string& host, const unsigned int& port) {
    struct addrinfo hints{}, *res;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(port);
    int status = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (status != 0) {
        throw std::runtime_error("getaddrinfo: " + std::string(gai_strerror(status)));
    }

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        freeaddrinfo(res);
        throw std::runtime_error("Failed to create socket");
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        freeaddrinfo(res);
        throw std::runtime_error("Connection failed");
    }

    freeaddrinfo(res);
}

SocketClient::~SocketClient() {
    close(sockfd);
}

std::string SocketClient::socketRequest(const std::string& payload) {
    std::lock_guard<std::mutex> lock(socket_mutex);

    if (send(sockfd, payload.c_str(), payload.size(), 0) < 0) {
        throw std::runtime_error("Failed to send data");
    }

    char buffer[1024];
    std::memset(buffer, 0, sizeof(buffer));
    ssize_t bytes_received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);

    if (bytes_received == 0) {
        throw std::runtime_error("Connection closed by peer");
    }

    if (bytes_received < 0) {
        throw std::runtime_error("Failed to receive response");
    }

    return std::string(buffer, bytes_received);
}