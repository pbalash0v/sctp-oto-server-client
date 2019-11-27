#include <string>
#include <thread>
#include <cstring>
#include <memory>


#include "sctp_srvr.h"

int main(int, char const**) {
	auto serv_cfg = std::make_shared<SCTPServer::Config>();
	serv_cfg->cert_filename = "../src/certs/server-cert.pem";
	serv_cfg->key_filename = "../src/certs/server-key.pem";

	SCTPServer s { serv_cfg };

	s.init();

	s.run();

	std::this_thread::sleep_for(std::chrono::milliseconds(1000));

	return EXIT_SUCCESS;
}
