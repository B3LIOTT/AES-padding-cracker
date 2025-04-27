#include <string>
#include <curl/curl.h>
#include <stdexcept>

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
