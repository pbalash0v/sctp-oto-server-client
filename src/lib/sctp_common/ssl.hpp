#pragma once

#include <functional>
#include <string>

#include <openssl/ssl.h>

namespace sctp
{

class SSLWrapper final
{
public:
	enum class Type
	{
		CLIENT,
		SERVER
	};
   
	explicit SSLWrapper(Type);

	SSLWrapper(const SSLWrapper& oth) = delete;
	SSLWrapper& operator=(const SSLWrapper& oth) = delete;
	SSLWrapper(SSLWrapper&& oth) = default;
	SSLWrapper& operator=(SSLWrapper&& oth) = default;

	~SSLWrapper();

	void init(const std::string& cert_file, const std::string& key_file);

	SSL_CTX* ctx_ {nullptr};

private:
	Type type_;
};

} //namespace sctp