#pragma once


#include <functional>
#include <string>

#include <openssl/ssl.h>


class SSL_h {
public:
   enum SSLType {
   	CLIENT,
      SERVER
   };
   
	SSL_h(SSLType);

	SSL_h(const SSL_h& oth) = delete;

	SSL_h& operator=(const SSL_h& oth) = delete;

	void init(const std::string& cert_file, const std::string& key_file);

	virtual ~SSL_h();

	SSL_CTX* ctx_ = nullptr;

private:
	SSLType type_;
};