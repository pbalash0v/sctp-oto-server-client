#include <iostream>
#include <cassert>
#include <usrsctp.h>
#include <netdb.h>

#include <unordered_map>
#include <algorithm>

#include "sctp_client.h"


#ifndef NDEBUG
#define log(level, text) \
						do { \
							if (nullptr == cfg_->debug_f) break; \
							std::string s = std::string(); \
							s += std::string(basename(__FILE__)) + \
							 + ", " + std::string(__func__) + \
							 + ":" + std::to_string(__LINE__) + \
							 + "\t " + std::string(text) + "\n"; \
								cfg_->debug_f(level, s); \
						} while (0)

#define CHECK_STATE() \
						do { \
							if (not (_check_state(std::string(__func__), state))) { \
								CRITICAL("Wrong state transition."); \
								throw std::logic_error("Disallowed state."); \
							} \
						} while (0)

#else
#define log(level, text) do {} while (0)
#define CHECK_STATE() do {} while (0)
#endif

#define TRACE(text) log(SCTPClient::TRACE, text)
#define DEBUG(text) log(SCTPClient::DEBUG, text)
#define INFO(text) log(SCTPClient::INFO, text)
#define WARNING(text) log(SCTPClient::WARNING, text)
#define ERROR(text) log(SCTPClient::ERROR, text)
#define CRITICAL(text) log(SCTPClient::CRITICAL, text)

#define TRACE_func_entry() TRACE("Entered " + std::string(__func__))
#define TRACE_func_left() TRACE("Left " + std::string(__func__))


constexpr auto BUFFERSIZE = 1 << 16; /* or use dynamic alloc with BIO_ctrl_pending(output_bio) ? */

/*
	Used to check whether function is allowed to run in some particular state
*/
static std::unordered_map<std::string, std::vector<SCTPClient::State>> state_allowed_funcs {
		{"init", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"run", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"sctp_send", std::vector<SCTPClient::State> { SCTPClient::SSL_CONNECTED }},
		{"udp_loop", std::vector<SCTPClient::State> { SCTPClient::SCTP_CONNECTING }},
		{"sctp_send_raw", std::vector<SCTPClient::State> 
			{ SCTPClient::SCTP_CONNECTING, SCTPClient::SCTP_CONNECTED, 
				SCTPClient::SSL_HANDSHAKING, SCTPClient::SSL_CONNECTED, SCTPClient::SSL_SHUTDOWN, }}
	};

static inline bool _check_state(const std::string& func_name, SCTPClient::State s) {
	const auto& vec = state_allowed_funcs[func_name];
	return (std::find(vec.cbegin(), vec.cend(), s) != vec.cend());
}



SCTPClient::SCTPClient() : SCTPClient(std::make_shared<SCTPClient::Config>()) {};

SCTPClient::SCTPClient(std::shared_ptr<SCTPClient::Config> p) : cfg_(p) {};

SCTPClient::~SCTPClient() {
	TRACE_func_entry();

	TRACE("About to join udp thread");
	if (udp_thr.joinable()) udp_thr.join();
	TRACE("udp thread joined");

	SSL_free(ssl);

	TRACE("About to usrsctp_close");
	usrsctp_close(sock);
	TRACE("usrsctp sock closed");

	TRACE("About to usrsctp_finish");
	bool finished_clean = false;
	for (int i = 0; i < 3; i++) {
		if (usrsctp_finish() != 0) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		} else {
			finished_clean = true;
			break;
		}
	}
	TRACE("usrsctp_finish " + std::string(((finished_clean) ? "clean" : "not clean")));

	TRACE_func_left();
}


void SCTPClient::set_state(SCTPClient::State new_state) {
	if (new_state == state) {
		CRITICAL("Wrong state transition.");
		throw std::logic_error("Wrong state transition.");
	}

	state = new_state;
	if (cfg_->state_f) cfg_->state_f(state);
}


void SCTPClient::handle_upcall(struct socket* sock, void* arg, [[maybe_unused]] int flgs) {
	SCTPClient* c = (SCTPClient *) arg;
	std::shared_ptr<SCTPClient::Config> cfg_ = c->cfg_;

	TRACE_func_entry();

	int events = usrsctp_get_events(sock);

	std::string m { "Socket events: "};
	if (events & SCTP_EVENT_ERROR) {
		m += "SCTP_EVENT_ERROR";
	}
	if (events & SCTP_EVENT_WRITE) {
		m += " SCTP_EVENT_WRITE";
	}
	if (events & SCTP_EVENT_READ) {
		m += " SCTP_EVENT_READ";
	}
	INFO(m);

	if (events & SCTP_EVENT_READ) { //&& c->state >= SCTPClient::SCTP_CONNECTED) {
		struct sctp_recvv_rn rn;
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));

		//struct sctp_rcvinfo rcv_info;
		ssize_t n;
		struct sockaddr_in addr;
		void* buf = calloc(1, BUFFERSIZE);
		int flags = 0;
		socklen_t from_len = (socklen_t) sizeof(struct sockaddr_in);
		unsigned int infotype;
		socklen_t infolen = sizeof(struct sctp_recvv_rn);
		//infolen = (socklen_t) sizeof(struct sctp_rcvinfo);

		while ((n = usrsctp_recvv(sock, buf, BUFFERSIZE, (struct sockaddr*) &addr, &from_len, (void *) &rn,
								&infolen, &infotype, &flags)) > 0) {

			if (n > 0) {
				if (flags & MSG_NOTIFICATION) {
					printf("Notification of length %llu received.\n", (unsigned long long) n);
				} else {
					c->handle_server_data(buf, n, addr, rn, infotype, flags);
				}
			} else if (n == 0) {
				// done = 1;
				// input_done = 1;
				usrsctp_deregister_address(c);
				usrsctp_close(c->sock);
				shutdown(c->udp_sock_fd, SHUT_RDWR);			
			} else {
				if (errno != EINTR) {
					free(buf);
					throw std::runtime_error(strerror(errno));
				}
			}

			free(buf);
		}
	}


	if (events & SCTP_EVENT_WRITE) { // && c->state < SCTPClient::SCTP_CONNECTED) {
		c->set_state(SCTPClient::SCTP_CONNECTED);

		// TODO: should be refactored into ssl_obj
		{
			c->ssl = SSL_new(c->ssl_obj.ctx_);
			c->output_bio = BIO_new(BIO_s_mem());
			c->input_bio = BIO_new(BIO_s_mem());

			assert(c->ssl); assert(c->output_bio); assert(c->input_bio);

			SSL_set_bio(c->ssl, c->input_bio, c->output_bio);

			SSL_set_connect_state(c->ssl);
		}
		int res = SSL_do_handshake(c->ssl);

		
		if (SSL_ERROR_WANT_READ == SSL_get_error(c->ssl, res) && BIO_ctrl_pending(c->output_bio)) {
				char outbuf[BIO_ctrl_pending(c->output_bio)] = { 0 };
				int read = BIO_read(c->output_bio, outbuf, sizeof(outbuf));
				assert(SSL_ERROR_NONE == SSL_get_error(c->ssl, read));

				if (c->sctp_send_raw(outbuf, read) < 0) throw std::runtime_error(strerror(errno));

				c->set_state(SCTPClient::SSL_HANDSHAKING);
				if (c->cfg_->state_f) c->cfg_->state_f(c->state);
		} else {
			throw std::runtime_error("SSL handshake error");
		}

		return;
	}



	TRACE_func_left();

}

/*
	SCTP engine wants to send data
*/
int SCTPClient::conn_output(void* arg, void *buf, size_t length, [[maybe_unused]] uint8_t tos, [[maybe_unused]] uint8_t set_df) {
	SCTPClient* c = (SCTPClient *) arg;
	std::shared_ptr<SCTPClient::Config> cfg_ = c->cfg_;

#if 0
	char* dump_buf;
	if ((dump_buf = usrsctp_dumppacket(buf, length, SCTP_DUMP_OUTBOUND)) != NULL) {
		debug(std::string(dump_buf));
		usrsctp_freedumpbuffer(dump_buf);
	}
#endif

	int numbytes = send(c->udp_sock_fd, buf, length, 0);

	if (numbytes < 0) {
		CRITICAL(strerror(errno));
		return (errno);
	} else {
		return (0);
	}
}


/* UDP init */
void SCTPClient::init_local_UDP() {
	int status;
	struct addrinfo* cli_info = NULL;   /* will point to the result */
	std::shared_ptr<struct addrinfo*> ptr (&cli_info,
					 [&](struct addrinfo** s) { if (*s) freeaddrinfo(*s); }); /* RAII for cli_info */

	struct addrinfo hints;

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;			// IPV4 only
	hints.ai_socktype = SOCK_DGRAM;  // UDP socket
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

	if ((status = getaddrinfo(NULL, std::to_string(cfg_->udp_encaps_port).c_str(),
		 &hints, &cli_info)) != 0) {
		throw std::runtime_error(gai_strerror(status));
	}

	// struct addrinfo {
	//   int              ai_flags;     // AI_PASSIVE, AI_CANONNAME, etc.
	//   int              ai_family;    // AF_INET, AF_INET6, AF_UNSPEC
	//   int              ai_socktype;  // SOCK_STREAM, SOCK_DGRAM
	//   int              ai_protocol;  // use 0 for "any"
	//   size_t           ai_addrlen;   // size of ai_addr in bytes
	//   struct sockaddr *ai_addr;      // struct sockaddr_in or _in6
	//   char            *ai_canonname; // full canonical hostname

	//   struct addrinfo *ai_next;      // linked list, next node
	//  }

	char ipstr[INET_ADDRSTRLEN];
	for (struct addrinfo* p = cli_info; p; p = p->ai_next) {
      struct sockaddr_in* ipv4 = (struct sockaddr_in *) p->ai_addr;
      void* addr = &(ipv4->sin_addr);
		inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
	}
	
	if ((udp_sock_fd = socket(cli_info->ai_family, cli_info->ai_socktype, cli_info->ai_protocol)) <= 0) {
		throw std::runtime_error(strerror(errno));
	}

	if (bind(udp_sock_fd, cli_info->ai_addr, cli_info->ai_addrlen) < 0) {
		throw std::runtime_error(strerror(errno));
	}
}


void SCTPClient::init_remote_UDP() {
	TRACE_func_entry();

	int status;
	struct addrinfo hints;
	struct addrinfo* serv_info;  // will point to the results
	std::shared_ptr<struct addrinfo*> ptr (&serv_info,
					 [&](struct addrinfo** s) { freeaddrinfo(*s); }); //RAII for servinfo

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_DGRAM; // TCP stream sockets

	if ((status = getaddrinfo(cfg_->server_address.c_str(),
		 std::to_string(cfg_->server_udp_port).c_str(), &hints, &serv_info)) != 0) {
		throw std::runtime_error(gai_strerror(status));
	}

	struct sockaddr* ipv4 = nullptr;
	bool found = false; //todo: ugly, need to look for sock API way
	for (struct addrinfo* p = serv_info; p; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			ipv4 = serv_info->ai_addr;
			found = true;
			break;
		}
      //struct sockaddr_in* ipv4 = (struct sockaddr_in*) p->ai_addr;
      //void* addr = &(ipv4->sin_addr);
		//inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
	}
	if (not found) throw std::runtime_error("Error resolving server address.");


	if (connect(udp_sock_fd, ipv4, sizeof (struct sockaddr_in)) < 0) {
		throw std::runtime_error(strerror(errno));
	}

	//connect our udp socket to remote server
	// struct sockaddr_in sin_s;
	// memset(&sin_s, 0, sizeof(struct sockaddr_in));
	// sin_s.sin_family = AF_INET;
	// sin_s.sin_port = htons(DEFAULT_SERVER_UDP_ENCAPS_PORT);
	// sin_s.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // ?


	// if (connect(udp_sock_fd, (struct sockaddr*) &sin_s, sizeof(struct sockaddr_in)) < 0) {
	// 	throw std::runtime_error(strerror(errno));
	// }

	TRACE_func_left();
}

/* 
	SCTP init
*/
void SCTPClient::init_SCTP() {
	TRACE_func_entry();

	void (*debug_printf)(const char *format, ...) = NULL;

	usrsctp_init(0, &conn_output, debug_printf);

	usrsctp_sysctl_set_sctp_blackhole(2); // TODO: ?
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0); // TODO: ?
	usrsctp_sysctl_set_sctp_ecn_enable(0); // TODO: ?
	usrsctp_register_address((void *) this); // TODO: ?

	int (*receive_cb)(struct socket*, union sctp_sockstore, void*, size_t, struct sctp_rcvinfo, int, void*) = NULL;
	int (*send_cb)(struct socket *sock, uint32_t sb_free)	= NULL;
	uint32_t sb_threshold = 0;
	void* recv_cback_data = NULL;

	if ((sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, 
					receive_cb = NULL, send_cb = NULL, sb_threshold, recv_cback_data = NULL)) == NULL) {
		throw std::runtime_error(strerror(errno));
	}

	uint16_t event_types[] = {	SCTP_ASSOC_CHANGE,
                       			SCTP_PEER_ADDR_CHANGE,
                       			SCTP_REMOTE_ERROR,
                       			SCTP_SHUTDOWN_EVENT,
                       			SCTP_ADAPTATION_INDICATION,
                       			SCTP_PARTIAL_DELIVERY_EVENT
                       		};
	struct sctp_event event;
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (auto ev_type : event_types) {
		event.se_type = ev_type;
		if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			ERROR("usrsctp_setsockopt SCTP_EVENT");
			throw std::runtime_error(std::string("setsockopt SCTP_EVENT: "));
		}
	}

	usrsctp_set_non_blocking(sock, 1); //TODO: check retval 
	usrsctp_set_upcall(sock, handle_upcall, this); //TODO: check retval 

	struct sockaddr_conn sconn;
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(0);
	sconn.sconn_addr = NULL; // ????????
	if (usrsctp_bind(sock, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		throw std::runtime_error(strerror(errno));
	}

	//no Nagle
	uint32_t optval = 1;
	if (usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &optval, sizeof(int)) < 0) {
		throw std::runtime_error(strerror(errno));
	}	

	TRACE_func_left();
}


void SCTPClient::init() {
	TRACE_func_entry();
	CHECK_STATE();

	try {
		ssl_obj.init(cfg_->cert_filename, cfg_->key_filename);
		init_local_UDP();
		init_remote_UDP();
		init_SCTP();
	} catch (const std::runtime_error& exc) {
		CRITICAL(exc.what());
		set_state(PURGE);		
	}

	TRACE_func_left();
}


void SCTPClient::run() {
	TRACE_func_entry();
	CHECK_STATE();

	set_state(SCTPClient::SCTP_CONNECTING);

	udp_thr = std::thread(&SCTPClient::udp_loop, this);

	struct sockaddr_conn sconn;
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(5001);
	//sconn.sconn_addr = &fd;
	sconn.sconn_addr = this; // ?

	//doesn't block
	int res = usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn));
	if (res < 0 && errno != EINPROGRESS) {
		throw std::runtime_error(strerror(errno));
	}

	TRACE_func_left();
}


void SCTPClient::stop() {
	TRACE_func_entry();

	TRACE("About to usrsctp_shutdown");
	/* async, should wait for ACK and handle rest in upcall */
	usrsctp_shutdown(sock, SHUT_RDWR);

	if (state == SCTP_CONNECTING) shutdown(udp_sock_fd, SHUT_RDWR);			

	TRACE_func_left();
}


ssize_t SCTPClient::sctp_send_raw(const void* buf, size_t len) {
	CHECK_STATE();

	if (sock == nullptr) throw std::runtime_error("socket doesn't exists");


	ssize_t sent; //TODO: default val ?

	if (state < SSL_CONNECTED) {
		// addrs - NULL for connected socket
		// addrcnt: Number of addresses.
		// As at most one address is supported, addrcnt is 0 if addrs is NULL and 1 otherwise.
		sent = usrsctp_sendv(sock, buf, len,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	} else {
		int written = SSL_write(ssl, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) throw std::runtime_error("SSL_write");
		assert(SSL_ERROR_NONE == SSL_get_error(ssl, written));

		assert(BIO_ctrl_pending(output_bio));

		char outbuf[BIO_ctrl_pending(output_bio)] = {0}; //size (???)

		int read = BIO_read(output_bio, outbuf, sizeof(outbuf));
		if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) throw std::runtime_error("BIO_read");
		assert(SSL_ERROR_NONE == SSL_get_error(ssl, read));

		sent = usrsctp_sendv(sock, outbuf, read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	}

	return sent;
}


ssize_t SCTPClient::sctp_send(const std::string& s) {
	return sctp_send_raw((void*)s.c_str(), s.size());
}

ssize_t SCTPClient::sctp_send(const void* buf, size_t len) {
	return sctp_send_raw(buf, len);
}

void SCTPClient::udp_loop() {
	TRACE_func_entry();
	CHECK_STATE();

 	char buf[BUFFERSIZE] = { 0 };

	try {
		while (true) {
			int numbytes = recv(udp_sock_fd, buf, BUFFERSIZE, 0);

	 		if (numbytes == 0) {  /* socket has been shutdown */
				break;
			}

			if (numbytes == -1) {
				if (errno != EINTR) {
					throw std::runtime_error(strerror(errno));
				}
				continue;
			}

			usrsctp_conninput(this, buf, (size_t) numbytes, 0); //TODO: check retval
		}
	} catch (const std::runtime_error& exc) {
		CRITICAL(exc.what());
	}

	set_state(PURGE);

	TRACE_func_left();
}


void SCTPClient::handle_server_data(void* buffer, ssize_t n, const struct sockaddr_in& addr,
					 const struct sctp_recvv_rn& rcv_info, unsigned int infotype, int flags) {
	char name[INET_ADDRSTRLEN];

	switch (state) {

	case SCTPClient::SSL_HANDSHAKING:
	{

		int written = BIO_write(input_bio, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) throw std::runtime_error("SSL_write");

		int res = SSL_do_handshake(ssl);

		if (not SSL_is_init_finished(ssl)) {
			if (SSL_ERROR_WANT_READ == SSL_get_error(ssl, res) && BIO_ctrl_pending(output_bio)) {
				char outbuf[BUFFERSIZE] = { 0 }; // size (?)
				int read = BIO_read(output_bio, outbuf, sizeof(outbuf));
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) throw std::runtime_error("BIO_read");

				if (sctp_send_raw(outbuf, read) < 0) throw std::runtime_error(strerror(errno));				
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, res) && BIO_ctrl_pending(output_bio)) {
				char outbuf[BUFFERSIZE] = {0}; // size (?)
				int read = BIO_read(output_bio, outbuf, sizeof(outbuf));
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) throw std::runtime_error("BIO_read");

				if (sctp_send_raw(outbuf, read) < 0) throw std::runtime_error(strerror(errno));

				set_state(SCTPClient::SSL_CONNECTED);
				if (cfg_->state_f) cfg_->state_f(state);
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, res) && !BIO_ctrl_pending(output_bio)) {
				set_state(SCTPClient::SSL_CONNECTED);
				if (cfg_->state_f) cfg_->state_f(state);
				break;
			}

		} else {
			if (BIO_ctrl_pending(output_bio)) {
				char outbuf[BUFFERSIZE] = {0}; // size (?)
				int read = BIO_read(output_bio, outbuf, sizeof(outbuf));
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) throw std::runtime_error("BIO_read");

				if (sctp_send_raw(outbuf, read) < 0) throw std::runtime_error(strerror(errno));
			}

			set_state(SCTPClient::SSL_CONNECTED);
			if (cfg_->state_f) cfg_->state_f(state);
		}
	}
	break;

	case SCTPClient::SSL_CONNECTED:
	{
		int written = BIO_write(input_bio, buffer, n);
		assert(SSL_ERROR_NONE == SSL_get_error(ssl, written));

		char outbuf[BUFFERSIZE] = { 0 }; /*  size (?) */
		int read = SSL_read(ssl, outbuf, sizeof outbuf);

		if (!read && SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl, read)) {
			set_state(SCTPClient::SSL_SHUTDOWN);
			break;
		}

		if (read < 0 && (SSL_ERROR_WANT_READ == SSL_get_error(ssl, read))) {
			DEBUG("SSL_ERROR_WANT_READ");
			break;
		}

		char message[BUFFERSIZE] = {'\0'};

		if (infotype == SCTP_RECVV_RCVINFO) {
			snprintf(message, sizeof message,
						"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u, complete %d.\n",
						(char*) outbuf,
						(unsigned long long) read,
						inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
						rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,	rcv_info.recvv_rcvinfo.rcv_tsn,
						ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context,
						(flags & MSG_EOR) ? 1 : 0);
		} else {
			snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u, complete %d.\n",
				(char*) outbuf,
				(unsigned long long) read,
				inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
				(flags & MSG_EOR) ? 1 : 0);
		}

		DEBUG(message);

		if (cfg_->data_cback_f) cfg_->data_cback_f(outbuf);
	}
	break;

	case SCTPClient::SCTP_CONNECTED:
	default:
		throw std::logic_error("Received data in unhandled client state.");
		break;
	}
}


std::ostream& operator<<(std::ostream& out, const SCTPClient::Config& c) {
	out << "local UDP encaps port: " << std::to_string(c.udp_encaps_port) << ", ";
	out << "server UDP encaps port: " << std::to_string(c.server_udp_port) << ", ";	
	out << "server address: " << c.server_address << ", ";
	out << "server SCTP port: " << std::to_string(c.server_sctp_port) << ", ";
	out << "data callback: " << (c.data_cback_f == nullptr ? "nullptr" : "set") << ", ";
	out << "debug callback: " << (c.debug_f == nullptr ? "nullptr" : "set") << ", ";
	out << "state callback: " << (c.state_f == nullptr ? "nullptr" : "set") << ", ";
	out << "SSL certificate: " << c.cert_filename << ", ";
	out << "SSL key: " << c.key_filename;
	
	return out;
}

std::ostream& operator<<(std::ostream& out, const SCTPClient& s) {
	out << *(s.cfg_);
	return out;
}