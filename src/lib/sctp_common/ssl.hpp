#ifndef __ssl_hpp__
#define __ssl_hpp__

#include <memory>
#include <functional>
#include <string>

#include <openssl/ssl.h>


namespace sctp
{
class cert_and_key;

class SSLWrapper final
{
public:
	enum class Type
	{
		CLIENT,
		SERVER
	};

	enum class CertAndKeyGenerator
	{
		DO_GENERATE,
		DO_NOT_GENERATE
	};

	explicit SSLWrapper(Type, CertAndKeyGenerator _ = CertAndKeyGenerator::DO_GENERATE);

	SSLWrapper(const SSLWrapper& oth) = delete;
	SSLWrapper& operator=(const SSLWrapper& oth) = delete;
	SSLWrapper(SSLWrapper&& oth) = default;
	SSLWrapper& operator=(SSLWrapper&& oth) = default;

	~SSLWrapper();

	std::unique_ptr<cert_and_key>& init(std::string cert_file, std::string key_file);

	SSL_CTX* ctx_{nullptr};

private:
	Type type_;
	CertAndKeyGenerator cert_and_key_gen_{CertAndKeyGenerator::DO_GENERATE};
	std::unique_ptr<cert_and_key> cert_and_key_ptr{nullptr};
};

} //namespace sctp

#endif // __ssl_hpp__