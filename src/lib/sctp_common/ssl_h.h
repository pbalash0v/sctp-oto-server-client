#pragma once

#include <functional>
#include <string>

#include <openssl/ssl.h>

namespace sctp
{

class SSL_h final
{
public:
	enum class Type
	{
		CLIENT,
		SERVER
	};
   
	explicit SSL_h(Type);

	SSL_h(const SSL_h& oth) = delete;
	SSL_h& operator=(const SSL_h& oth) = delete;
	SSL_h(SSL_h&& oth) = default;
	SSL_h& operator=(SSL_h&& oth) = default;

	~SSL_h();

	void init(const std::string& cert_file, const std::string& key_file);

	SSL_CTX* ctx_ {nullptr};

private:
	Type type_;
};

} //namespace sctp