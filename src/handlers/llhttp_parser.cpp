#include "llhttp_parser.h"
#include <cstring>
#include <iostream>

LLHTTPParser::LLHTTPParser() : parsing_header_field_(false) {
    // Initialisation des settings llhttp
    llhttp_settings_init(&settings_);
    
    // Configuration des callbacks
    settings_.on_message_begin = OnMessageBegin;
    settings_.on_url = OnUrl;
    settings_.on_header_field = OnHeaderField;
    settings_.on_header_value = OnHeaderValue;
    settings_.on_headers_complete = OnHeadersComplete;
    settings_.on_body = OnBody;
    settings_.on_message_complete = OnMessageComplete;
    
    // Initialisation du parser en mode REQUEST
    llhttp_init(&parser_, HTTP_REQUEST, &settings_);
    parser_.data = this;  // Pointeur vers l'instance C++ pour les callbacks
}

LLHTTPParser::~LLHTTPParser() {
    // Pas de cleanup nécessaire pour llhttp (stack-allocated)
}

bool LLHTTPParser::Parse(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return false;
    }
    
    // llhttp_execute retourne HPE_OK si succès, ou code d'erreur
    enum llhttp_errno err = llhttp_execute(&parser_, reinterpret_cast<const char*>(data), length);
    
    if (err != HPE_OK) {
        // Erreur de parsing (peut arriver si données incomplètes ou malformées)
        return false;
    }
    
    return true;
}

void LLHTTPParser::Reset() {
    // Reset du parser pour une nouvelle requête
    llhttp_init(&parser_, HTTP_REQUEST, &settings_);
    parser_.data = this;
    
    // Reset de la requête actuelle
    request_ = HTTPRequest();
    current_header_field_.clear();
    current_header_value_.clear();
    parsing_header_field_ = false;
}

// ========== CALLBACKS LLHTTP ==========

int LLHTTPParser::OnMessageBegin(llhttp_t* parser) {
    // Appelé au début de la requête HTTP
    return 0;  // 0 = succès
}

int LLHTTPParser::OnUrl(llhttp_t* parser, const char* at, size_t length) {
    LLHTTPParser* self = static_cast<LLHTTPParser*>(parser->data);
    self->request_.url.append(at, length);
    
    // Extraction de la méthode HTTP depuis llhttp
    if (parser->method != 0) {
        self->request_.method = llhttp_method_name(static_cast<llhttp_method_t>(parser->method));
    }
    
    return 0;
}

int LLHTTPParser::OnHeaderField(llhttp_t* parser, const char* at, size_t length) {
    LLHTTPParser* self = static_cast<LLHTTPParser*>(parser->data);
    
    // Si on était sur une valeur, on sauvegarde le header précédent
    if (!self->parsing_header_field_ && !self->current_header_field_.empty()) {
        self->request_.headers[self->current_header_field_] = self->current_header_value_;
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }
    
    self->current_header_field_.append(at, length);
    self->parsing_header_field_ = true;
    
    return 0;
}

int LLHTTPParser::OnHeaderValue(llhttp_t* parser, const char* at, size_t length) {
    LLHTTPParser* self = static_cast<LLHTTPParser*>(parser->data);
    self->current_header_value_.append(at, length);
    self->parsing_header_field_ = false;
    
    return 0;
}

int LLHTTPParser::OnHeadersComplete(llhttp_t* parser) {
    LLHTTPParser* self = static_cast<LLHTTPParser*>(parser->data);
    
    // Sauvegarde du dernier header
    if (!self->current_header_field_.empty()) {
        self->request_.headers[self->current_header_field_] = self->current_header_value_;
        self->current_header_field_.clear();
        self->current_header_value_.clear();
    }
    
    // Version HTTP
    self->request_.version = "HTTP/1." + std::to_string(parser->http_minor);
    
    return 0;
}

int LLHTTPParser::OnBody(llhttp_t* parser, const char* at, size_t length) {
    LLHTTPParser* self = static_cast<LLHTTPParser*>(parser->data);
    self->request_.body.append(at, length);
    
    return 0;
}

int LLHTTPParser::OnMessageComplete(llhttp_t* parser) {
    LLHTTPParser* self = static_cast<LLHTTPParser*>(parser->data);
    
    // La requête HTTP est complète !
    self->request_.complete = true;
    
    return 0;
}
