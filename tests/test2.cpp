#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <cstring>
#include <memory>
#include <cassert>
#include <limits>
#include <unistd.h>
#include <cstdio>
#include <cassert>
#include <exception>

#include "sctp_srvr.h"
#include "sctp_srvr_client.h"


std::atomic_bool running { true };

//
class BrokenSCTPServer_usrsctp_socket : public SCTPServer {
public:
	BrokenSCTPServer_usrsctp_socket(std::shared_ptr<SCTPServer::Config> ptr) 
	: SCTPServer(ptr) {};

protected:
	struct socket* usrsctp_socket(int, int, int,
               int (*)(struct socket* sock, union sctp_sockstore addr, void *data,
                                 size_t datalen, struct sctp_rcvinfo, int flags, void *ulp_info),
               int (*)(struct socket *sock, uint32_t sb_free),
               uint32_t , void*) override {
		return NULL;
	};
};

//
class BrokenSCTPServer_usrsctp_bind : public SCTPServer {
public:
	BrokenSCTPServer_usrsctp_bind(std::shared_ptr<SCTPServer::Config> ptr) 
	: SCTPServer(ptr) {};

protected:
	int usrsctp_bind(struct socket*, struct sockaddr*, socklen_t) override {
		std::cerr << "in usrsctp_bind override" << std::endl;
		return -1;
	};
};

//
class BrokenSCTPServer_usrsctp_listen : public SCTPServer {
public:
	BrokenSCTPServer_usrsctp_listen(std::shared_ptr<SCTPServer::Config> ptr) 
	: SCTPServer(ptr) {};

protected:
	int usrsctp_listen(struct socket*, int) override {
		return -1;
	};
};

//
class BrokenSCTPServer_bad_SSL_fname : public SCTPServer {
public:
	BrokenSCTPServer_bad_SSL_fname(std::shared_ptr<SCTPServer::Config> ptr) 
	: SCTPServer(ptr) {};
};

std::shared_ptr<SCTPServer::Config> get_cfg() {
	auto serv_cfg = std::make_shared<SCTPServer::Config>();
	serv_cfg->cert_filename = "../src/certs/server-cert.pem";
	serv_cfg->key_filename = "../src/certs/server-key.pem";
	serv_cfg->debug_f = [](auto, auto s) { std::cerr << s << std::endl; };
	return serv_cfg;	
}


int main(int, char const**) {
	std::cerr << "***BrokenSCTPServer_bad_SSL_fname cert_filename" << std::endl;
	{
		BrokenSCTPServer_bad_SSL_fname server { get_cfg() };
		server.cfg_->cert_filename = "NONEXISTANT";

		try {
			server.init();
		} catch (const std::runtime_error& exc) {
			assert(strstr(exc.what(), "SSL_CTX_use_certificate_file"));
		}
	}

	std::cerr << "***BrokenSCTPServer_bad_SSL_fname key_filename" << std::endl;
	{
		BrokenSCTPServer_bad_SSL_fname server { get_cfg() };
		server.cfg_->key_filename = "NONEXISTANT";
		try {
			server.init();
		} catch (const std::runtime_error& exc) {
			assert(strstr(exc.what(), "SSL_CTX_use_PrivateKey_file"));
		}
	}

	std::cerr << "***BrokenSCTPServer_usrsctp_socket" << std::endl;
	{
		BrokenSCTPServer_usrsctp_socket server { get_cfg() };

		try {
			server.init();
		} catch (const std::runtime_error& exc) {
			assert(strstr(exc.what(), "usrsctp_socket"));
		}
	}
	
	std::cerr << "***BrokenSCTPServer_usrsctp_bind" << std::endl;
	{
		BrokenSCTPServer_usrsctp_bind server { get_cfg() };

		try {
			server.init();
		} catch (const std::runtime_error& exc) {
			assert(strstr(exc.what(), "usrsctp_bind"));
		}
	}

	std::cerr << "BrokenSCTPServer_usrsctp_bind" << std::endl;
	{
		BrokenSCTPServer_usrsctp_listen server { get_cfg() };

		try {
			server.init();
		} catch (const std::runtime_error& exc) {
			assert(strstr(exc.what(), "usrsctp_listen"));
		}
	}

	return EXIT_SUCCESS;
}
