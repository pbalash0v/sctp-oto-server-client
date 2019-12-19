#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>

#include <usrsctp.h>
#include <netdb.h>

#include <cassert>
#include <cstring>

#include "sctp_client.h"


#ifndef NDEBUG
#define log(level, text) \
						do { \
							if (nullptr == cfg_->debug_cback_f) break; \
							std::string s = std::string(); \
							s += std::string(basename(__FILE__)) + \
							 + ", " + std::string(__func__) + \
							 + ":" + std::to_string(__LINE__) + \
							 + "\t " + std::string(text) + "\n"; \
								cfg_->debug_cback_f(level, s); \
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
static std::map<std::string, std::vector<SCTPClient::State>> state_allowed_funcs {
		{"init", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"init_usrsctp_lib", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"init_local_UDP", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"init_local_UDP", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"init_remote_UDP", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"init_SCTP", std::vector<SCTPClient::State> { SCTPClient::NONE }},
		{"operator()", std::vector<SCTPClient::State> { SCTPClient::INITIALIZED }},
		{"send", std::vector<SCTPClient::State> { SCTPClient::SSL_CONNECTED }},
		{"udp_loop", std::vector<SCTPClient::State> { SCTPClient::SCTP_CONNECTING }},
		{"send_raw_", std::vector<SCTPClient::State> 
			{ SCTPClient::SCTP_CONNECTING, SCTPClient::SCTP_CONNECTED, 
				SCTPClient::SSL_HANDSHAKING, SCTPClient::SSL_CONNECTED, SCTPClient::SSL_SHUTDOWN, }}
};

static std::map<SCTPClient::State, std::string> state_names {
	{ SCTPClient::NONE, "NONE" },
	{ SCTPClient::INITIALIZED, "INITIALIZED" },
	{ SCTPClient::SCTP_CONNECTING, "SCTP_CONNECTING"},
	{ SCTPClient::SCTP_CONNECTED, "SCTP_CONNECTED"},
	{ SCTPClient::SSL_HANDSHAKING, "SSL_HANDSHAKING"},
	{ SCTPClient::SSL_CONNECTED, "SSL_CONNECTED"},
	{ SCTPClient::SSL_SHUTDOWN, "SSL_SHUTDOWN"},
	{ SCTPClient::PURGE, "PURGE"}
};

static inline bool _check_state(const std::string& func_name, SCTPClient::State s)
{
	const auto& vec = state_allowed_funcs[func_name];
	return (std::find(vec.cbegin(), vec.cend(), s) != vec.cend());
}



SCTPClient::SCTPClient() : SCTPClient(std::make_shared<SCTPClient::Config>()) {};

SCTPClient::SCTPClient(std::shared_ptr<SCTPClient::Config> p) : cfg_(p) {
	sctp_msg_buff_.reserve(cfg_->message_size*2);
	decrypted_msg_buff_.reserve(cfg_->message_size*2);
	encrypted_msg_buff_.reserve(cfg_->message_size*2);
};

SCTPClient::~SCTPClient()
{
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


void SCTPClient::set_state(SCTPClient::State new_state)
{
	TRACE_func_entry();

	if (new_state == state) {
		CRITICAL("Wrong state transition.");
		throw std::logic_error("Wrong state transition.");
	}

	TRACE(state_names[state] + " -> " + state_names[new_state]);

	state = new_state;

	if (cfg_->state_cback_f) cfg_->state_cback_f(state);

	TRACE_func_left();
}


void SCTPClient::handle_upcall(struct socket* sock, void* arg, int /* flgs */)
{
	SCTPClient* c = static_cast<SCTPClient*>(arg);
	std::shared_ptr<SCTPClient::Config> cfg_ = c->cfg_;
	/* from here on we can use log macros */

	//TRACE_func_entry();

	int events = usrsctp_get_events(sock);

#if 0
	TRACE(([&]
	{
		std::string s = { "Socket events: " };

		if (events & SCTP_EVENT_ERROR) {
			s += "SCTP_EVENT_ERROR";
		}
		if (events & SCTP_EVENT_WRITE) {
			s += " SCTP_EVENT_WRITE";
		}
		if (events & SCTP_EVENT_READ) {
			s += " SCTP_EVENT_READ";
		}

		return s;
	})());
#endif

	if (events & SCTP_EVENT_WRITE) {
		//TRACE("SCTP_EVENT_WRITE: unhandled.");
	}

	/* handling ??? */
	if (events & SCTP_EVENT_ERROR) {
		ERROR("SCTP_EVENT_ERROR: " + std::string(strerror(errno)));
	}

	if (events & SCTP_EVENT_READ) {
		TRACE("handling SCTP_EVENT_READ");

		struct sctp_recvv_rn rn;
		memset(&rn, 0, sizeof(struct sctp_recvv_rn));

		//struct sctp_rcvinfo rcv_info;
		ssize_t n = 0;
		struct sockaddr_in addr;
		int flags = 0;
		socklen_t from_len = (socklen_t) sizeof(struct sockaddr_in);
		unsigned int infotype;
		socklen_t infolen = sizeof(struct sctp_recvv_rn);
		//infolen = (socklen_t) sizeof(struct sctp_rcvinfo);
		char recv_buf[1<<16] = { 0 };

		/* we can have several notifications/data waiting. process them all */
		while ((n = usrsctp_recvv(sock, recv_buf, sizeof recv_buf,
								(struct sockaddr*)&addr, &from_len,
								static_cast<void *>(&rn),
								&infolen, &infotype, &flags)) > 0) {

			if (not (flags & MSG_EOR)) {
				TRACE("usrsctp_recvv incomplete: " + std::to_string(n));
				c->sctp_msg_buff_.insert(c->sctp_msg_buff_.end(), recv_buf, recv_buf + n);
				flags = 0;
				memset(recv_buf, 0, sizeof recv_buf);
				continue;
 			} else {
				if (not c->sctp_msg_buff_.empty())
					c->sctp_msg_buff_.insert(c->sctp_msg_buff_.end(), recv_buf, recv_buf + n);
			}

			n = (c->sctp_msg_buff_.empty()) ? n : c->sctp_msg_buff_.size();
			void* data_buf = (c->sctp_msg_buff_.empty()) ? recv_buf : c->sctp_msg_buff_.data();

			try {
				if (flags & MSG_NOTIFICATION) {
					TRACE("Notification of length "
						+ std::to_string((unsigned long long) n) + std::string(" received."));
					c->handle_notification(static_cast<union sctp_notification*>(data_buf), n);
				} else {
					TRACE("Socket data of length " 
						+ std::to_string((unsigned long long) n) + std::string(" received."));					
					c->handle_server_data(data_buf, n, addr, rn, infotype);
				}
			} catch (const std::runtime_error& exc) {
				ERROR(exc.what());
			}

			c->sctp_msg_buff_.clear();
			flags = 0;
		}


		if (n == 0) {
			TRACE("Socket shutdown");
			//usrsctp_deregister_address(c); // ?
			//usrsctp_close(c->sock);
			//shutdown(c->udp_sock_fd, SHUT_RDWR);			
		}

		if (n < 0) {
			if ((errno == EAGAIN) or 
				(errno == EWOULDBLOCK) or 
				(errno == EINTR)) {
				//TRACE(strerror(errno));
			} else {
				CRITICAL(strerror(errno));
			}
		}
	}

	//TRACE_func_left();
}

/*
	Callback for SCTP engine data 
	(e.g. when it wants to send data it calls this func).
	We send through our udp socket.
	Return value, probably, handled by usrsctp (?)
*/
int SCTPClient::conn_output(void* arg, void *buf, size_t length,
									 uint8_t /* tos */, uint8_t /* set_df */)
{
	SCTPClient* c = static_cast<SCTPClient*>(arg);
	std::shared_ptr<SCTPClient::Config> cfg_ = c->cfg_;

#if 0
	char* dump_buf;
	if ((dump_buf = usrsctp_dumppacket(buf, length, SCTP_DUMP_OUTBOUND)) != NULL) {
		debug(std::string(dump_buf));
		usrsctp_freedumpbuffer(dump_buf);
	}
#endif

	int numbytes = ::send(c->udp_sock_fd, buf, length, 0);

	if (numbytes < 0) {
		CRITICAL(strerror(errno));
		return errno;
	} else {
		return 0;
	}
}


/* UDP init */
void SCTPClient::init_local_UDP()
{
	CHECK_STATE();
	TRACE_func_entry();

	int status;
	struct addrinfo* cli_info = NULL; /* will point to the result */
	/* RAII for cli_info */
	std::shared_ptr<struct addrinfo*> ptr (&cli_info,
					 [&](struct addrinfo** s) { if (*s) freeaddrinfo(*s); });
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
		TRACE(ipstr);
		memset(ipstr, 0, sizeof ipstr);
	}
	
	if ((udp_sock_fd = socket(cli_info->ai_family, cli_info->ai_socktype, cli_info->ai_protocol)) <= 0) {
		throw std::runtime_error(strerror(errno));
	}

	if (bind(udp_sock_fd, cli_info->ai_addr, cli_info->ai_addrlen) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	TRACE_func_left();
}


void SCTPClient::init_remote_UDP()
{
	CHECK_STATE();
	TRACE_func_entry();

	int status;

	struct addrinfo* serv_info = nullptr;  // will point to the results
	std::shared_ptr<struct addrinfo*> ptr (&serv_info,
					 [&](struct addrinfo** s) { freeaddrinfo(*s); }); //RAII for servinfo

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_DGRAM; // TCP stream sockets

	if ((status = getaddrinfo(cfg_->server_address.c_str(),
		 std::to_string(cfg_->server_udp_port).c_str(), &hints, &serv_info)) != 0) {
		throw std::runtime_error(gai_strerror(status));
	}

	TRACE(cfg_->server_address + " " + std::to_string(cfg_->server_udp_port));

	struct sockaddr* ipv4 = nullptr;
	bool found = false; //todo: this is ugly, need to look for sock API way
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

void SCTPClient::init_usrsctp_lib()
{
	CHECK_STATE();
	TRACE_func_entry();

	if (usrsctp_lib_initialized) return;

	void (*debug_printf)(const char *format, ...) = NULL;


	usrsctp_init(0, &conn_output, debug_printf);

	usrsctp_sysctl_set_sctp_blackhole(2); // TODO: ?
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0); // TODO: ?

  	/* Disable the Explicit Congestion Notification extension */
	usrsctp_sysctl_set_sctp_ecn_enable(0);
	usrsctp_register_address((void *) this); // TODO: ?

	usrsctp_lib_initialized = true;

	TRACE_func_left();
}


/* 
	SCTP init
*/
void SCTPClient::init_SCTP()
{
	CHECK_STATE();
	TRACE_func_entry();

	int (*receive_cb)(struct socket*, union sctp_sockstore, void*, size_t, struct sctp_rcvinfo, int, void*) = NULL;
	int (*send_cb)(struct socket *sock, uint32_t sb_free)	= NULL;
	uint32_t sb_threshold = 0;
	void* recv_cback_data = NULL;

	if ((sock = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, 
					receive_cb, send_cb, sb_threshold, recv_cback_data)) == NULL) {
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

	auto bufsize = 5*1024*1024;
	if (usrsctp_setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(int)) < 0) {
		throw std::runtime_error("setsockopt: rcvbuf" + std::string(strerror(errno)));
	}

	if (usrsctp_setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(int)) < 0) {
		throw std::runtime_error("setsockopt: sndbuf" + std::string(strerror(errno)));
	}

	TRACE_func_left();
}


void SCTPClient::init()
{
	CHECK_STATE();
	TRACE_func_entry();

	try {
		ssl_obj.init(cfg_->cert_filename, cfg_->key_filename);
		init_local_UDP();
		init_remote_UDP();
		init_usrsctp_lib();
		init_SCTP();
	} catch (const std::runtime_error& exc) {
		CRITICAL(exc.what());
		set_state(PURGE);
		throw;
	}

	set_state(SCTPClient::INITIALIZED);

	TRACE_func_left();
}


void SCTPClient::operator()()
{
	CHECK_STATE();
	TRACE_func_entry();

	set_state(SCTPClient::SCTP_CONNECTING);

	udp_thr = std::thread(&SCTPClient::udp_loop, this);

	struct sockaddr_conn sconn;
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	sconn.sconn_port = htons(cfg_->server_sctp_port);
	//sconn.sconn_addr = &fd;
	sconn.sconn_addr = this; // ??????

	//doesn't block
	int res = usrsctp_connect(sock, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn));
	if (res < 0 && errno != EINPROGRESS) {
		throw std::runtime_error(strerror(errno));
	}

	TRACE_func_left();
}


void SCTPClient::stop()
{
	TRACE_func_entry();

	if (sock) {
		TRACE("About to usrsctp_shutdown SHUT_WR");
		/* 
			(we are not going to send anything more, so SHUT_WR)
			Call is async, we should handle assoc notification in upcall.
		 */
		usrsctp_shutdown(sock, SHUT_WR);
	}

	if (state == SCTP_CONNECTING) shutdown(udp_sock_fd, SHUT_RDWR);			

	TRACE_func_left();
}


ssize_t SCTPClient::send_raw_(const void* buf, size_t len)
{
	assert(sock);
	CHECK_STATE();

	ssize_t sent = -1;

	if (state != SCTPClient::SSL_CONNECTED) {
		// addrs - NULL for connected socket
		// addrcnt: Number of addresses.
		// As at most one address is supported, addrcnt is 0 if addrs is NULL and 1 otherwise.
		sent = usrsctp_sendv(sock, buf, len,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	} else {
		int written = SSL_write(ssl, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) {
			throw std::runtime_error("SSL_write");
		}

		encrypted_msg_buff_.clear();
		encrypted_msg_buff_.resize(BIO_ctrl_pending(output_bio));

		int read = BIO_read(output_bio, 
					encrypted_msg_buff_.data(), encrypted_msg_buff_.size());
		if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
			throw std::runtime_error("BIO_read");
		}
		
		sent = usrsctp_sendv(sock, encrypted_msg_buff_.data(), read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
		TRACE("Sent: " + std::to_string(sent)
				 + std::string(". Errno: ") + std::string(strerror(errno)));

	}

	return sent;
}


ssize_t SCTPClient::send(const void* buf, size_t len)
{
	return send_raw_(buf, len);
}

/*
	Reads from raw udp socket in a loop
*/
void SCTPClient::udp_loop()
{
	CHECK_STATE();
	TRACE_func_entry();

 	char buf[BUFFERSIZE] = { 0 };

	try {
		while (true) {
			int numbytes = recv(udp_sock_fd, buf, BUFFERSIZE, 0);

	 		if (numbytes == 0) {  /* socket has been shutdown */
				break;
			}

			if (numbytes < 0) {
				if (errno != EINTR) {
					throw std::runtime_error(strerror(errno));
				}
				continue;
			}

			usrsctp_conninput(this, buf, (size_t) numbytes, /* ecn_bits */ 0);
		}
	} catch (const std::runtime_error& exc) {
		CRITICAL(exc.what());
	}

	set_state(PURGE);

	TRACE_func_left();
}


void SCTPClient::handle_server_data(void* buffer, ssize_t n, const struct sockaddr_in& addr,
					 const struct sctp_recvv_rn& rcv_info, unsigned int infotype)
{
	TRACE(state_names[state]);

	#define MAX_TLS_RECORD_SIZE (1 << 14)
	size_t outbuf_len = (state != SCTPClient::SSL_CONNECTED) ?
								MAX_TLS_RECORD_SIZE : n;

	decrypted_msg_buff_.clear();
	decrypted_msg_buff_.resize(outbuf_len);
	void* outbuf = decrypted_msg_buff_.data();

	switch (state) {
	case SCTPClient::SSL_HANDSHAKING:
	{

		int written = BIO_write(input_bio, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(ssl, written)) throw std::runtime_error("SSL_write");

		int res = SSL_do_handshake(ssl);

		if (not SSL_is_init_finished(ssl)) {
			if (SSL_ERROR_WANT_READ == SSL_get_error(ssl, res) and BIO_ctrl_pending(output_bio)) {
				int read = BIO_read(output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					throw std::runtime_error("BIO_read");
				}
				if (send_raw_(outbuf, read) < 0) {
					throw std::runtime_error(strerror(errno));
				}
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, res) and BIO_ctrl_pending(output_bio)) {
				int read = BIO_read(output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
					throw std::runtime_error("BIO_read");
				}
				if (send_raw_(outbuf, read) < 0) {
					throw std::runtime_error(strerror(errno));
				}

				set_state(SCTPClient::SSL_CONNECTED);
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl, res) and !BIO_ctrl_pending(output_bio)) {
				set_state(SCTPClient::SSL_CONNECTED);
				break;
			}

		} else {
			if (BIO_ctrl_pending(output_bio)) {
				int read = BIO_read(output_bio, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) throw std::runtime_error("BIO_read");

				if (send_raw_(outbuf, read) < 0) throw std::runtime_error(strerror(errno));
			}

			set_state(SCTPClient::SSL_CONNECTED);
		}
	}
	break;

	case SCTPClient::SSL_CONNECTED:
	{
		TRACE(std::string("encrypted message length n: ") + std::to_string(n));

		size_t total_decrypted_message_size = 0;

		int written = BIO_write(input_bio, buffer, n);
		assert(SSL_ERROR_NONE == SSL_get_error(ssl, written));

		do {
			int read = SSL_read(ssl, static_cast<char*>(outbuf) + total_decrypted_message_size, MAX_TLS_RECORD_SIZE);
			//TRACE(std::string("SSL read: ") + std::to_string(read));

			if (read == 0 and SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl, read)) {
				set_state(SCTPClient::SSL_SHUTDOWN);
				break;
			}

			if (read < 0 and (SSL_ERROR_WANT_READ == SSL_get_error(ssl, read))) {
				WARNING("SSL_ERROR_WANT_READ");
				break;
			}

			assert(SSL_ERROR_NONE == SSL_get_error(ssl, written));

			total_decrypted_message_size += read;
		} while (BIO_ctrl_pending(input_bio));

		DEBUG(([&]
		{
			char message[BUFFERSIZE] = {'\0'};
			char name[INET_ADDRSTRLEN];

			if (infotype == SCTP_RECVV_RCVINFO) {
				snprintf(message, sizeof message,
							"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.\n",
							(char*) outbuf,
							(unsigned long long) total_decrypted_message_size,
							inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
							rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,	rcv_info.recvv_rcvinfo.rcv_tsn,
							ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context);
			} else {
					if (n < 30) 
						snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u",
							(char*) outbuf,
							(unsigned long long) total_decrypted_message_size,
							inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
							ntohs(addr.sin_port));
					else 
						snprintf(message, sizeof message, "Msg of length %llu received from %s:%u",
							(unsigned long long) total_decrypted_message_size,
							inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
							ntohs(addr.sin_port));
			}

			return std::string(message);
		})());

		if (cfg_->data_cback_f) {
			try {
				cfg_->data_cback_f(std::make_unique<SCTPClient::Data>(outbuf, total_decrypted_message_size));
			} catch (...) {
				CRITICAL("Exception in user data_cback function.");
			}
		}
	}
	break;

	case SCTPClient::SCTP_CONNECTED:
	default:
		throw std::logic_error("Received data in unhandled client state.");
		break;
	}
}



void SCTPClient::handle_association_change_event(struct sctp_assoc_change* sac)
{
	unsigned int i, n;

	/*
		Preapre debug message for association change
	*/
	auto message = ([&]
	{
		std::string message { "Association change " };

		switch (sac->sac_state) {
			case SCTP_COMM_UP:
				message += "SCTP_COMM_UP";
				break;
			case SCTP_COMM_LOST:
				message += "SCTP_COMM_LOST";
				break;
			case SCTP_RESTART:
				message += "SCTP_RESTART";
				break;
			case SCTP_SHUTDOWN_COMP:
				message += "SCTP_SHUTDOWN_COMP";
				break;
			case SCTP_CANT_STR_ASSOC:
				message += "SCTP_CANT_STR_ASSOC";
				break;
			default:
				message += "UNKNOWN";
				break;
		}


		message += ", streams (in/out) = (";
		message += std::to_string(sac->sac_inbound_streams);
		message += "/";
		message += std::to_string(sac->sac_outbound_streams);
		message += ")";


		n = sac->sac_length - sizeof(struct sctp_assoc_change);

		if (((sac->sac_state == SCTP_COMM_UP) or
		     (sac->sac_state == SCTP_RESTART)) and (n > 0)) {
			message += ", supports";
			for (i = 0; i < n; i++) {
				switch (sac->sac_info[i]) {
				case SCTP_ASSOC_SUPPORTS_PR:
					message += " PR";
					break;
				case SCTP_ASSOC_SUPPORTS_AUTH:
					message += " AUTH";
					break;
				case SCTP_ASSOC_SUPPORTS_ASCONF:
					message += " ASCONF";
					break;
				case SCTP_ASSOC_SUPPORTS_MULTIBUF:
					message += " MULTIBUF";
					break;
				case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
					message += " RE-CONFIG";
					break;
				default:
					message += " UNKNOWN(0x";
					message += std::to_string(sac->sac_info[i]);
					message += ")";
					break;
				}
			}
		} else if (((sac->sac_state == SCTP_COMM_LOST) or
		            (sac->sac_state == SCTP_CANT_STR_ASSOC)) and (n > 0)) {
			message += ", ABORT =";
			for (i = 0; i < n; i++) {
				message += " 0x";
				message += std::to_string(sac->sac_info[i]);
			}
		}

		message += ".\n";

		return message;
	})();
	DEBUG(message);



	/*
		Real association change handling
	*/
	switch (sac->sac_state) {
		case SCTP_COMM_UP:
			{
				set_state(SCTPClient::SCTP_CONNECTED);

				// TODO: should be refactored into ssl_obj
				{
					ssl = SSL_new(ssl_obj.ctx_);
					output_bio = BIO_new(BIO_s_mem());
					input_bio = BIO_new(BIO_s_mem());

					assert(ssl); assert(output_bio); assert(input_bio);

					SSL_set_bio(ssl, input_bio, output_bio);

					SSL_set_connect_state(ssl);
				}
				int res = SSL_do_handshake(ssl);
				assert(BIO_ctrl_pending(output_bio));

				set_state(SCTPClient::SSL_HANDSHAKING);
				if (SSL_ERROR_WANT_READ == SSL_get_error(ssl, res)) {
						char outbuf[MAX_TLS_RECORD_SIZE] = { 0 };
						int read = BIO_read(output_bio, outbuf, sizeof(outbuf));
						if (SSL_ERROR_NONE != SSL_get_error(ssl, read)) {
							throw std::runtime_error("BIO_read");
						}

						if (send_raw_(outbuf, read) < 0) {
							throw std::runtime_error(strerror(errno));
						}

				} else {
					throw std::runtime_error("SSL handshake error");
				}
			}
			break;
		case SCTP_COMM_LOST:
			break;
		case SCTP_RESTART:
			break;
		case SCTP_SHUTDOWN_COMP:
			usrsctp_deregister_address(this); // ?
			usrsctp_close(sock);
			 /* this should wake recv in udp thread */
			shutdown(udp_sock_fd, SHUT_RDWR);
			break;
		case SCTP_CANT_STR_ASSOC:
			break;
		default:
			break;
	}

	return;
}

void SCTPClient::handle_shutdown_event(struct sctp_shutdown_event*)
{
	char buf[BUFFERSIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Shutdown event.\n");
	DEBUG(buf);
	/* XXX: notify all channels. */
	return;
}

void SCTPClient::handle_peer_address_change_event(struct sctp_paddr_change* spc)
{
	char addr_buf[INET6_ADDRSTRLEN];
	const char* addr;
	char buf[BUFFERSIZE] = { '\0' };
	struct sockaddr_in *sin;
	struct sockaddr_in6* sin6;
	struct sockaddr_conn* sconn;

	switch (spc->spc_aaddr.ss_family) {
		case AF_INET:
			sin = (struct sockaddr_in *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET, &sin->sin_addr, addr_buf, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
			addr = inet_ntop(AF_INET6, &sin6->sin6_addr, addr_buf, INET6_ADDRSTRLEN);
			break;
		case AF_CONN:
			sconn = (struct sockaddr_conn *)&spc->spc_aaddr;
			snprintf(addr_buf, INET6_ADDRSTRLEN, "%p", sconn->sconn_addr);
			addr = addr_buf;
			break;
		default:
			snprintf(addr_buf, INET6_ADDRSTRLEN, "Unknown family %d", spc->spc_aaddr.ss_family);
			addr = addr_buf;
			break;
	}

	int written = snprintf(buf, sizeof buf, "Peer address %s is now ", addr);

	switch (spc->spc_state) {
		case SCTP_ADDR_AVAILABLE:
			written += snprintf(buf + written , sizeof(buf) - written, "SCTP_ADDR_AVAILABLE");
			break;
		case SCTP_ADDR_UNREACHABLE:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_UNREACHABLE");
			break;
		case SCTP_ADDR_REMOVED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_REMOVED");
			break;
		case SCTP_ADDR_ADDED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_ADDED");
			break;
		case SCTP_ADDR_MADE_PRIM:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_MADE_PRIM");
			break;
		case SCTP_ADDR_CONFIRMED:
			written += snprintf(buf + written,  sizeof(buf) - written, "SCTP_ADDR_CONFIRMED");
			break;
		default:
			written += snprintf(buf + written,  sizeof(buf) - written, "UNKNOWN");
			break;
	}

	snprintf(buf + written, sizeof(buf) - written, " (error = 0x%08x).\n", spc->spc_error);

	DEBUG(buf);
	return;
}

void SCTPClient::handle_send_failed_event(struct sctp_send_failed_event* ssfe)
{
	size_t i, n;

	if (ssfe->ssfe_flags & SCTP_DATA_UNSENT) {
		fprintf(stderr, "Unsent ");
	}

	if (ssfe->ssfe_flags & SCTP_DATA_SENT) {
		fprintf(stderr, "Sent ");
	}

	if (ssfe->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
		fprintf(stderr, "(flags = %x) ", ssfe->ssfe_flags);
	}

	fprintf(stderr, "message with PPID = %u, SID = %u, flags: 0x%04x due to error = 0x%08x",
	       ntohl(ssfe->ssfe_info.snd_ppid), ssfe->ssfe_info.snd_sid,
	       ssfe->ssfe_info.snd_flags, ssfe->ssfe_error);

	n = ssfe->ssfe_length - sizeof(struct sctp_send_failed_event);
	for (i = 0; i < n; i++) {
		fprintf(stderr, " 0x%02x", ssfe->ssfe_data[i]);
	}

	fprintf(stderr, ".\n");
	return;
}

void SCTPClient::handle_adaptation_indication(struct sctp_adaptation_event* sai)
{
	char buf[BUFFERSIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Adaptation indication: %x.\n", sai-> sai_adaptation_ind);
	DEBUG(buf);
	return;
}



void SCTPClient::handle_stream_reset_event(struct sctp_stream_reset_event* strrst)
{
	uint32_t n, i;

	n = (strrst->strreset_length - sizeof(struct sctp_stream_reset_event)) / sizeof(uint16_t);
	fprintf(stderr, "Stream reset event: flags = %x, ", strrst->strreset_flags);
	if (strrst->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
		if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
			fprintf(stderr, "incoming/");
		}
		fprintf(stderr, "incoming ");
	}
	if (strrst->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
		fprintf(stderr, "outgoing ");
	}
	fprintf(stderr, "stream ids = ");
	for (i = 0; i < n; i++) {
		if (i > 0) {
			fprintf(stderr, ", ");
		}
		fprintf(stderr, "%d", strrst->strreset_stream_list[i]);
	}
	fprintf(stderr, ".\n");
	return;
}

void SCTPClient::handle_stream_change_event(struct sctp_stream_change_event* strchg)
{
	char buf[BUFFERSIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Stream change event: streams (in/out) = (%u/%u), flags = %x.\n",
	       strchg->strchange_instrms, strchg->strchange_outstrms, strchg->strchange_flags);
	DEBUG(buf);

	return;
}

void SCTPClient::handle_remote_error_event(struct sctp_remote_error* sre)
{
	size_t i, n;

	n = sre->sre_length - sizeof(struct sctp_remote_error);

	int written = 0;
	char buf[BUFFERSIZE] = { '\0' };
	written = snprintf(buf, sizeof buf, "Remote Error (error = 0x%04x): ", sre->sre_error);
	for (i = 0; i < n; i++) {
		written += snprintf(buf + written, sizeof buf - written, " 0x%02x", sre-> sre_data[i]);
	}

	DEBUG(std::string(buf) + ".\n");

	return;
}

void SCTPClient::handle_notification(union sctp_notification* notif, size_t n)
{
	TRACE_func_entry();

	if (notif->sn_header.sn_length != (uint32_t) n) {
		return;
	}
	std::string message { "handle_notification : " };

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		message += "SCTP_ASSOC_CHANGE\n";
		DEBUG(message);
		handle_association_change_event(&(notif->sn_assoc_change));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		message += "SCTP_PEER_ADDR_CHANGE\n";
		DEBUG(message);
		handle_peer_address_change_event(&(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		message += "SCTP_REMOTE_ERROR\n";
		DEBUG(message);
		handle_remote_error_event(&(notif->sn_remote_error));
		break;
	case SCTP_SHUTDOWN_EVENT:
		message += "SCTP_SHUTDOWN_EVENT\n";
		DEBUG(message);
		handle_shutdown_event(&(notif->sn_shutdown_event));
		break;
	case SCTP_ADAPTATION_INDICATION:
		message += "SCTP_ADAPTATION_INDICATION\n";
		DEBUG(message);
		handle_adaptation_indication(&(notif->sn_adaptation_event));
		break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
		message += "SCTP_PARTIAL_DELIVERY_EVENT\n";
		DEBUG(message);
		break;
	case SCTP_AUTHENTICATION_EVENT:
		message += "SCTP_AUTHENTICATION_EVENT\n";
		DEBUG(message);		
		break;
	case SCTP_SENDER_DRY_EVENT:
		message += "SCTP_SENDER_DRY_EVENT\n";
		DEBUG(message);		
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
		message += "SCTP_NOTIFICATIONS_STOPPED_EVENT\n";
		DEBUG(message);		
		break;
	case SCTP_SEND_FAILED_EVENT:
		message += "SCTP_SEND_FAILED_EVENT\n";
		DEBUG(message);		
		handle_send_failed_event(&(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		message += "SCTP_STREAM_RESET_EVENT\n";
		DEBUG(message);
		handle_stream_reset_event(&(notif->sn_strreset_event));
		break;
	case SCTP_ASSOC_RESET_EVENT:
		message += "SCTP_ASSOC_RESET_EVENT\n";
		DEBUG(message);
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		message += "SCTP_STREAM_CHANGE_EVENT\n";
		DEBUG(message);
		handle_stream_change_event(&(notif->sn_strchange_event));
		break;
	default:
		break;
	}


	TRACE_func_left();
}


std::string SCTPClient::to_string() const
{
	std::ostringstream oss;
	oss << *this;
	return oss.str();
}


std::ostream& operator<<(std::ostream& out, const SCTPClient::Config& c)
{
	out << "local UDP encaps port: " << std::to_string(c.udp_encaps_port) << ", ";
	out << "server UDP encaps port: " << std::to_string(c.server_udp_port) << ", ";	
	out << "server address: " << c.server_address << ", ";
	out << "server SCTP port: " << std::to_string(c.server_sctp_port) << ", ";
	out << "data callback: " << (c.data_cback_f == nullptr ? "nullptr" : "set") << ", ";
	out << "debug callback: " << (c.debug_cback_f == nullptr ? "nullptr" : "set") << ", ";
	out << "state callback: " << (c.state_cback_f == nullptr ? "nullptr" : "set") << ", ";
	out << "SSL certificate: " << c.cert_filename << ", ";
	out << "SSL key: " << c.key_filename;
	
	return out;
}


std::ostream& operator<<(std::ostream& out, const SCTPClient& s)
{
	out << *(s.cfg_);
	return out;
}