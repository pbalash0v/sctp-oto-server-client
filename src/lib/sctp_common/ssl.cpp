#include <iostream>
#include <string.h>

#include <openssl/err.h>

#include "ssl.hpp"
#include "helper.hpp"


namespace sctp
{

SSLWrapper::SSLWrapper(SSLWrapper::Type type, CertAndKeyGenerator g)
	: type_{type}
	, cert_and_key_gen_{g}
{
}

SSLWrapper::~SSLWrapper()
{
	if (nullptr != ctx_) SSL_CTX_free(ctx_);	
}


std::unique_ptr<cert_and_key>& SSLWrapper::init(std::string cert_file, std::string key_file)
{
	// bool is_client = (type_ == SSLWrapper::CLIENT);

	/* SSL library initialisation */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	/* 
		create the SSL server context
		SSLv23_client_method() or TLS_client_method()
		SSLv23_server_method() or TLS_server_method()

	*/

#ifndef TLS_MAX_VERSION
	Error: Your OpenSSL version does not support TLS.
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	#define CLIENT_METHOD TLSv1_2_client_method
	#define SERVER_METHOD TLSv1_2_server_method
#else
	#define CLIENT_METHOD TLS_client_method
	#define SERVER_METHOD TLS_server_method
#endif

	ctx_ = SSL_CTX_new((type_ == SSLWrapper::Type::CLIENT) ? CLIENT_METHOD() : SERVER_METHOD());

	if (!ctx_) throw std::runtime_error("SSL_CTX_new()");

	/* the client doesn't have to send it's certificate */
	SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER, [](int, X509_STORE_CTX*) { return 1; });

	#if 0
	/* Load certificate and private key files, and check consistency */
	char certfile[1024] = {'\0'};
	char keyfile[1024] = {'\0'};

	if (cert_file == std::string() && key_file == std::string()) {
		std::string type_s = is_client ? "client" : "server";
		snprintf(certfile, sizeof certfile, "../certs/%s-cert.pem", type_s.c_str());
		snprintf(keyfile, sizeof keyfile, "../certs/%s-key.pem", type_s.c_str());
	} else {
		snprintf(certfile, sizeof certfile, "%s", cert_file.c_str());
		snprintf(keyfile, sizeof keyfile, "%s", key_file.c_str());
	}

	#endif

	if ((cert_file.empty() or key_file.empty())
		and (cert_and_key_gen_ == CertAndKeyGenerator::DO_GENERATE))
	{
		cert_and_key_ptr = std::make_unique<cert_and_key>();
		cert_file = cert_and_key_ptr->cert();
		key_file = cert_and_key_ptr->key();
	}

	if (SSL_CTX_use_certificate_file(ctx_, cert_file.c_str(),  SSL_FILETYPE_PEM) != 1)
		throw std::runtime_error("SSL_CTX_use_certificate_file");

	if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1)
		throw std::runtime_error("SSL_CTX_use_PrivateKey_file");

	/* Make sure the key and certificate file match. */
	if (SSL_CTX_check_private_key(ctx_) != 1)
		throw std::runtime_error("SSL_CTX_check_private_key");

	/* Recommended to avoid SSLv2 & SSLv3 */
	#define OPTIONS SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1
	SSL_CTX_set_options(ctx_, OPTIONS);

	#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
	if (SSL_CTX_set_cipher_list(ctx_, CIPHER_LIST) != 1)
		throw std::runtime_error("SSL_CTX_set_cipher_list");

	return cert_and_key_ptr;
}


} //namespace sctp
