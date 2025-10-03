#ifndef LLHTTP_PARSER_H
#define LLHTTP_PARSER_H

#include <string>
#include <map>
#include <memory>
#include <cstdint>
#include "llhttp.h"

/**
 * Wrapper ultra-rapide pour llhttp (10-20x plus rapide que le parser manuel)
 */
class LLHTTPParser {
public:
    struct HTTPRequest {
        std::string method;
        std::string url;
        std::string version;
        std::map<std::string, std::string> headers;
        std::string body;
        bool complete;
        
        HTTPRequest() : complete(false) {}
    };

    LLHTTPParser();
    ~LLHTTPParser();

    // Parse des données HTTP (peut être appelé plusieurs fois pour TCP fragments)
    bool Parse(const uint8_t* data, size_t length);
    
    // Récupère la requête complète (si disponible)
    const HTTPRequest& GetRequest() const { return request_; }
    
    // Vérifie si la requête HTTP est complète
    bool IsComplete() const { return request_.complete; }
    
    // Reset le parser pour une nouvelle requête
    void Reset();

private:
    // Callbacks statiques pour llhttp (appelés par la librairie C)
    static int OnMessageBegin(llhttp_t* parser);
    static int OnUrl(llhttp_t* parser, const char* at, size_t length);
    static int OnHeaderField(llhttp_t* parser, const char* at, size_t length);
    static int OnHeaderValue(llhttp_t* parser, const char* at, size_t length);
    static int OnHeadersComplete(llhttp_t* parser);
    static int OnBody(llhttp_t* parser, const char* at, size_t length);
    static int OnMessageComplete(llhttp_t* parser);

    llhttp_t parser_;
    llhttp_settings_t settings_;
    HTTPRequest request_;
    std::string current_header_field_;
    std::string current_header_value_;
    bool parsing_header_field_;
};

#endif // LLHTTP_PARSER_H
