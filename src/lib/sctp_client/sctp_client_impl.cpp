#include <iostream>
#include <sstream>
#include <map>
#include <algorithm>
#include <cstring>

#include <netdb.h>
#include <sys/socket.h> 

#include <boost/assert.hpp>

#include <usrsctp.h>

#include "sync_queue.hpp"
#include "sctp_client_impl.hpp"
#include "logging.hpp"
#include "ssl.hpp"


namespace
{

constexpr auto BUFFERSIZE {1 << 16};
constexpr auto MAX_TLS_RECORD_SIZE  {1 << 14};
/*
	Used to check whether function is allowed to run in some particular state
*/
std::map<std::string, std::vector<sctp::Client::State>> state_allowed_funcs {
		{"init", std::vector<sctp::Client::State> { sctp::Client::State::NONE }},
		{"init_usrsctp_lib", std::vector<sctp::Client::State> { sctp::Client::State::NONE }},
		{"init_local_UDP", std::vector<sctp::Client::State> { sctp::Client::State::NONE }},
		{"init_remote_UDP", std::vector<sctp::Client::State> { sctp::Client::State::NONE }},
		{"init_SCTP", std::vector<sctp::Client::State> { sctp::Client::State::NONE }},
		{"operator()", std::vector<sctp::Client::State> { sctp::Client::State::INITIALIZED }},
		{"send", std::vector<sctp::Client::State> { sctp::Client::State::SSL_CONNECTED }},
		{"udp_recv_loop", std::vector<sctp::Client::State> { sctp::Client::State::SCTP_CONNECTING }},
		{"handle_raw_udp_data_loop", std::vector<sctp::Client::State> { sctp::Client::State::SCTP_CONNECTING }},
		{"send_raw", std::vector<sctp::Client::State> 
			{ sctp::Client::State::SCTP_CONNECTING, sctp::Client::State::SCTP_CONNECTED, 
				sctp::Client::State::SSL_HANDSHAKING, sctp::Client::State::SSL_CONNECTED, sctp::Client::State::SSL_SHUTDOWN, }}
};

std::map<sctp::Client::State, std::string> state_names {
	{ sctp::Client::State::NONE, "NONE" },
	{ sctp::Client::State::INITIALIZED, "INITIALIZED" },
	{ sctp::Client::State::SCTP_CONNECTING, "SCTP_CONNECTING"},
	{ sctp::Client::State::SCTP_CONNECTED, "SCTP_CONNECTED"},
	{ sctp::Client::State::SSL_HANDSHAKING, "SSL_HANDSHAKING"},
	{ sctp::Client::State::SSL_CONNECTED, "SSL_CONNECTED"},
	{ sctp::Client::State::SSL_SHUTDOWN, "SSL_SHUTDOWN"},
	{ sctp::Client::State::PURGE, "PURGE"}
};

std::map<uint16_t, std::string> notification_names {
	{ SCTP_ASSOC_CHANGE, "SCTP_ASSOC_CHANGE" },
	{ SCTP_PEER_ADDR_CHANGE, "SCTP_PEER_ADDR_CHANGE" },
	{ SCTP_REMOTE_ERROR, "SCTP_REMOTE_ERROR"},
	{ SCTP_SEND_FAILED, "SCTP_SEND_FAILED"},
	{ SCTP_SHUTDOWN_EVENT, "SCTP_SHUTDOWN_EVENT"},
	{ SCTP_ADAPTATION_INDICATION, "SCTP_ADAPTATION_INDICATION"},
	{ SCTP_PARTIAL_DELIVERY_EVENT, "SCTP_PARTIAL_DELIVERY_EVENT"},
	{ SCTP_AUTHENTICATION_EVENT, "SCTP_AUTHENTICATION_EVENT"},
	{ SCTP_SENDER_DRY_EVENT, "SCTP_SENDER_DRY_EVENT"},
	{ SCTP_STREAM_RESET_EVENT, "SCTP_STREAM_RESET_EVENT"},
	{ SCTP_NOTIFICATIONS_STOPPED_EVENT, "SCTP_NOTIFICATIONS_STOPPED_EVENT"},
	{ SCTP_ASSOC_RESET_EVENT, "SCTP_ASSOC_RESET_EVENT"},
	{ SCTP_STREAM_CHANGE_EVENT, "SCTP_STREAM_CHANGE_EVENT"},
	{ SCTP_SEND_FAILED_EVENT, "SCTP_SEND_FAILED_EVENT"}
};	

inline bool _check_state(const std::string& func_name, sctp::Client::State s)
{
	const auto& vec = state_allowed_funcs[func_name];
	return (std::find(vec.cbegin(), vec.cend(), s) != vec.cend());
}

} //anon namespace


namespace sctp
{


ClientImpl::ClientImpl(std::shared_ptr<Client::Config> p)
	: cfg_ {p}
	, ssl_obj_ {std::make_unique<SSLWrapper>(SSLWrapper::Type::CLIENT)}
	, raw_udp_data_ {std::make_unique<SyncQueue<std::unique_ptr<std::vector<char>>>>()}
{
	sctp_msg_buff_.reserve(cfg_->message_size*2);
	decrypted_msg_buff_.reserve(cfg_->message_size*2);
	encrypted_msg_buff_.reserve(cfg_->message_size*2);
	(*ClientImpl::number_of_instances_ptr_)++;

	init();
};

ClientImpl::~ClientImpl()
{
	TRACE_func_entry();

	TRACE("About to join udp receive thread");
	if (udp_recv_thr_.joinable()) udp_recv_thr_.join();
	TRACE("udp receive thread joined");

	TRACE("About to join udp data handling thread");
	if (udp_data_thr_.joinable()) udp_data_thr_.join();
	TRACE("udp data handling thread joined");

	SSL_free(ssl_);

	usrsctp_deregister_address(this); // ?

	TRACE("About to usrsctp_close");
	usrsctp_close(sock_);
	TRACE("usrsctp sock closed");

	(*ClientImpl::number_of_instances_ptr_)--;

	if (*ClientImpl::number_of_instances_ptr_ == 0) {
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
	}

	TRACE_func_left();
}


void ClientImpl::state(Client::State new_state)
{
	if (new_state == state_) {
		CRITICAL("Wrong state transition.");
		throw std::logic_error("Wrong state transition.");
	}

	TRACE(state_names[state_] + " -> " + state_names[new_state]);

	switch (new_state) {
	case Client::State::SCTP_CONNECTED:
		// TODO: should be refactored into ssl_obj
		ssl_ = SSL_new(ssl_obj_->ctx_);
		output_bio_ = BIO_new(BIO_s_mem());
		input_bio_ = BIO_new(BIO_s_mem());
		BOOST_ASSERT(ssl_); BOOST_ASSERT(output_bio_); BOOST_ASSERT(input_bio_);

		SSL_set_bio(ssl_, input_bio_, output_bio_);

		SSL_set_connect_state(ssl_);
		break;
	case Client::State::SSL_HANDSHAKING:
		{
			int res = SSL_do_handshake(ssl_);

			if (SSL_ERROR_WANT_READ == SSL_get_error(ssl_, res)) {
				char outbuf[MAX_TLS_RECORD_SIZE] = { 0 };
				int read = BIO_read(output_bio_, outbuf, sizeof(outbuf));
				if (SSL_ERROR_NONE != SSL_get_error(ssl_, read)) {
					throw std::runtime_error("BIO_read");
				}

				if (send_raw(outbuf, read) < 0) {
					throw std::runtime_error(strerror(errno));
				}
			} else {
				throw std::runtime_error("SSL handshake error");
			}	
		}
		break;
	case Client::State::PURGE:
		/* end udp data processing thread by queueing empty data*/
		//raw_udp_data_.enqueue(std::make_unique<sctp::Data>());
		raw_udp_data_->enqueue(std::make_unique<std::vector<char>>());		
		break;

	default:
		break;
	}

	state_ = new_state;

	if (cfg_->state_cback_f) {
		try {
			cfg_->state_cback_f(state_);
		} catch (...) {
			CRITICAL("Exception in user state_cback function");
		}
	}
}


void ClientImpl::handle_upcall(struct socket* sock, void* arg, int /* flgs */)
{
	ClientImpl* c = static_cast<ClientImpl*>(arg);
	std::shared_ptr<Client::Config>& cfg_ = c->cfg_;
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
			TRACE("SCTP socket has been shutdown");
			 /* this should wake recv in udp thread */
			shutdown(c->udp_sock_fd_, SHUT_RDWR);
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
int ClientImpl::conn_output(void* arg, void *buf, size_t length,
									 uint8_t /* tos */, uint8_t /* set_df */)
{
	ClientImpl* c = static_cast<ClientImpl*>(arg);
	std::shared_ptr<Client::Config> cfg_ = c->cfg_;

#if 0
	char* dump_buf;
	if ((dump_buf = usrsctp_dumppacket(buf, length, SCTP_DUMP_OUTBOUND)) != NULL) {
		debug(std::string(dump_buf));
		usrsctp_freedumpbuffer(dump_buf);
	}
#endif

	int numbytes = ::send(c->udp_sock_fd_, buf, length, 0);

	if (numbytes < 0) {
		CRITICAL(strerror(errno));
		return errno;
	} else {
		return 0;
	}
}


/* UDP init */
void ClientImpl::init_local_UDP()
{
	CHECK_STATE();
	TRACE_func_entry();

	int status;
	struct addrinfo* cli_info = NULL; /* will point to the result */
	/* RAII for cli_info */
	std::unique_ptr<struct addrinfo, std::function<void(struct addrinfo*)>> cli_info_ptr
		 (NULL, [&](auto s) { freeaddrinfo(s); });

	struct addrinfo hints;

	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;			// IPV4 only
	hints.ai_socktype = SOCK_DGRAM;  // UDP socket
	hints.ai_flags = AI_PASSIVE;     // fill in my IP for me

	if ((status = getaddrinfo(NULL, std::to_string(cfg_->udp_encaps_port).c_str(),
		 &hints, &cli_info)) != 0) {
		throw std::runtime_error(gai_strerror(status));
	} else {
		cli_info_ptr.reset(cli_info);
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
		TRACE(ipstr + std::string(":") + std::to_string(ipv4->sin_port));
		memset(ipstr, 0, sizeof ipstr);
	}
	
	if ((udp_sock_fd_ = socket(cli_info->ai_family, cli_info->ai_socktype, cli_info->ai_protocol)) <= 0) {
		throw std::runtime_error(strerror(errno));
	}

	if (bind(udp_sock_fd_, cli_info->ai_addr, cli_info->ai_addrlen) < 0) {
		throw std::runtime_error(strerror(errno));
	}

	TRACE_func_left();
}


void ClientImpl::init_remote_UDP()
{
	CHECK_STATE();
	TRACE_func_entry();

	int status;

	struct addrinfo* serv_info { nullptr };  // will point to the results
	std::unique_ptr<struct addrinfo, std::function<void(struct addrinfo*)>> serv_info_ptr
		 (NULL, [&](auto s) { freeaddrinfo(s); });

	struct addrinfo hints;
	memset(&hints, 0, sizeof hints); // make sure the struct is empty
	hints.ai_family = AF_INET;     // don't care IPv4 or IPv6
	hints.ai_socktype = SOCK_DGRAM; // TCP stream sockets

	if ((status = getaddrinfo(cfg_->server_address.c_str(),
		 std::to_string(cfg_->server_udp_port).c_str(), &hints, &serv_info)) != 0) {
		throw std::runtime_error(gai_strerror(status));
	} else {
		serv_info_ptr.reset(serv_info);
	}

	TRACE(cfg_->server_address + " " + std::to_string(cfg_->server_udp_port));

	struct sockaddr* ipv4 { nullptr };
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


	if (connect(udp_sock_fd_, ipv4, sizeof (struct sockaddr_in)) < 0) {
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

void ClientImpl::init_usrsctp_lib()
{
	CHECK_STATE();
	TRACE_func_entry();

	if (*usrsctp_lib_initialized_ptr_) return;

	void (*debug_printf)(const char *format, ...) = NULL;

	usrsctp_init(0, &conn_output, debug_printf);

	usrsctp_sysctl_set_sctp_blackhole(2); // TODO: ?
	usrsctp_sysctl_set_sctp_no_csum_on_loopback(0); // TODO: ?

  	/* Disable the Explicit Congestion Notification extension */
	usrsctp_sysctl_set_sctp_ecn_enable(0);

	*usrsctp_lib_initialized_ptr_ = true;

	TRACE_func_left();
}


/* 
	SCTP init
*/
void ClientImpl::init_SCTP()
{
	CHECK_STATE();
	TRACE_func_entry();

	usrsctp_register_address(static_cast<void *>(this)); // TODO: ?

	using recv_cb_type = int (*)(struct socket*, union sctp_sockstore, void*, size_t, struct sctp_rcvinfo, int, void*);
	using send_cb_type = int (*)(struct socket *sock, uint32_t sb_free, void* ulp_info);
	recv_cb_type r_cb {nullptr};
	send_cb_type s_cb {nullptr};
	uint32_t sb_threshold = 0;
	void* ulp_info {nullptr};

	if ((sock_ = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, r_cb, s_cb, sb_threshold, ulp_info)) == NULL)
	{
		throw std::runtime_error(strerror(errno));
	}

	uint16_t event_types[] = {	SCTP_ASSOC_CHANGE,
                       			SCTP_PEER_ADDR_CHANGE,
                       			SCTP_REMOTE_ERROR,
                       			SCTP_SHUTDOWN_EVENT,
                       			SCTP_ADAPTATION_INDICATION,
                       			SCTP_PARTIAL_DELIVERY_EVENT,
                       			SCTP_SENDER_DRY_EVENT
                       		};
	struct sctp_event event;
	memset(&event, 0, sizeof(event));
	event.se_assoc_id = SCTP_ALL_ASSOC;
	event.se_on = 1;
	for (auto ev_type : event_types) {
		event.se_type = ev_type;
		if (usrsctp_setsockopt(sock_, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0) {
			ERROR("usrsctp_setsockopt SCTP_EVENT");
			throw std::runtime_error(std::string("setsockopt SCTP_EVENT: "));
		}
	}

	usrsctp_set_non_blocking(sock_, 1);
	usrsctp_set_upcall(sock_, handle_upcall, this);

	// get bound UDP port
   struct sockaddr_in bound;
   socklen_t len = sizeof bound;
	if (getsockname(udp_sock_fd_, (struct sockaddr*) &bound, &len) < 0) {
		throw std::runtime_error(strerror(errno));
	}
	TRACE("Bound udp encaps port: " + std::to_string(htons(bound.sin_port)));
	bound_udp_encaps_port_ = bound.sin_port;

	//bind sctp (use discovered bound udp port)
	struct sockaddr_conn sconn;
	memset(&sconn, 0, sizeof(struct sockaddr_conn));
	sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
	sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
	/* 
		Setting sconn.sconn_port = 0 should (supposedly) tell usrsctp engine
		to provide us with a free unused port number.
		This doesn't happen. Second instance of client gets the same sctp port assigned.
		So the workaround is to use port, acquired on udp socket bind
		or try one provided in cfg object.
	*/
	sconn.sconn_port = (cfg_->sctp_port == 0) ? bound.sin_port : htons(cfg_->sctp_port);
	sconn.sconn_addr = this;
	if (usrsctp_bind(sock_, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn)) < 0) {
		throw std::runtime_error(strerror(errno));
	}

	//no Nagle
	uint32_t optval = 1;
	if (usrsctp_setsockopt(sock_, IPPROTO_SCTP, SCTP_NODELAY, &optval, sizeof(int)) < 0) {
		throw std::runtime_error(strerror(errno));
	}

	// send/recv buffers
	auto bufsize = 1024*1024;
	if (usrsctp_setsockopt(sock_, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(int)) < 0) {
		throw std::runtime_error("setsockopt: rcvbuf" + std::string(strerror(errno)));
	}
	if (usrsctp_setsockopt(sock_, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(int)) < 0) {
		throw std::runtime_error("setsockopt: sndbuf" + std::string(strerror(errno)));
	}

	TRACE_func_left();
}


void ClientImpl::init()
{
	CHECK_STATE();
	TRACE_func_entry();

	try
	{
		ssl_obj_->init(cfg_->cert_filename, cfg_->key_filename);
		init_local_UDP();
		init_remote_UDP();
		init_usrsctp_lib();
		init_SCTP();
	}
	catch (const std::runtime_error& exc)
	{
		CRITICAL(exc.what());
		state(Client::State::PURGE);
		throw;
	}

	state(Client::State::INITIALIZED);

	TRACE_func_left();
}


void ClientImpl::operator()()
{
	CHECK_STATE();
	TRACE_func_entry();

	state(Client::State::SCTP_CONNECTING);

	udp_recv_thr_ = std::thread {&ClientImpl::udp_recv_loop, this};
	udp_data_thr_ = std::thread {&ClientImpl::handle_raw_udp_data_loop, this};

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
	int res = usrsctp_connect(sock_, (struct sockaddr *)&sconn, sizeof(struct sockaddr_conn));
	if ((res < 0) and (errno != EINPROGRESS))
	{
		throw std::runtime_error(strerror(errno));
	}

	TRACE_func_left();
}


void ClientImpl::stop()
{
	TRACE_func_entry();

	if (sock_) {
		TRACE("About to usrsctp_shutdown SHUT_WR");
		/* 
			(we are not going to send anything more, so SHUT_WR)
			Call is async, we should handle assoc notification in upcall.
		 */
		usrsctp_shutdown(sock_, SHUT_WR);
	}

	if (state_ == Client::State::SCTP_CONNECTING) shutdown(udp_sock_fd_, SHUT_RDWR);

	TRACE_func_left();
}


ssize_t ClientImpl::send_raw(const void* buf, size_t len)
{
	BOOST_ASSERT(sock_);
	CHECK_STATE();

	ssize_t sent = -1;

	if (state_ != Client::State::SSL_CONNECTED) {
		// addrs - NULL for connected socket
		// addrcnt: Number of addresses.
		// As at most one address is supported, addrcnt is 0 if addrs is NULL and 1 otherwise.
		sent = usrsctp_sendv(sock_, buf, len,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	} else {
		int written = SSL_write(ssl_, buf, len);
		if (SSL_ERROR_NONE != SSL_get_error(ssl_, written)) {
			throw std::runtime_error("send_raw_: SSL_write");
		}

		encrypted_msg_buff_.clear();
		encrypted_msg_buff_.resize(BIO_ctrl_pending(output_bio_));

		int read = BIO_read(output_bio_, 
					encrypted_msg_buff_.data(), encrypted_msg_buff_.size());
		if (SSL_ERROR_NONE != SSL_get_error(ssl_, read)) {
			throw std::runtime_error("send_raw_: BIO_read");
		}
		
		sent = usrsctp_sendv(sock_, encrypted_msg_buff_.data(), read,
						 /* addrs */ NULL, /* addrcnt */ 0,
						  /* info */ NULL, /* infolen */ 0,
						   SCTP_SENDV_NOINFO, /* flags */ 0);
	}

	if (sent < 0) {
		WARNING("usrsctp_sendv: " + std::string(strerror(errno)));
		throw std::runtime_error("usrsctp_sendv: " + std::string(strerror(errno)));
	}

	TRACE("Sent: " + std::to_string(sent) + std::string(". Errno: ") + std::string(strerror(errno)));
	
	return sent;
}


ssize_t ClientImpl::send(const void* buf, size_t len)
{
	if (*sender_dry_ptr_) {
		*sender_dry_ptr_ = false;
		return send_raw(buf, len);
	} else {
		throw std::runtime_error("sender_dry");
	}
}

/*
	Reads from raw udp socket in a loop
	and enqueues.
*/
void ClientImpl::udp_recv_loop()
{
	CHECK_STATE();
	TRACE_func_entry();

 	char buf[BUFFERSIZE] = { 0 };

	try
	{
		while (true) {
			int numbytes = recv(udp_sock_fd_, buf, BUFFERSIZE, 0);

	 		if (numbytes == 0) {  /* socket has been shutdown */
				break;
			}

			if (numbytes < 0) {
				if (errno != EINTR) {
					throw std::runtime_error(strerror(errno));
				} else {
					continue;
				}
			}

			//raw_udp_data_.enqueue(std::make_unique<sctp::Data>(buf, numbytes));
			raw_udp_data_->enqueue(std::make_unique<std::vector<char>>(buf, buf+numbytes));
		}
	}
	catch (const std::runtime_error& exc)
	{
		CRITICAL(exc.what());
	}

	state(Client::State::PURGE);

	TRACE_func_left();
}

void ClientImpl::handle_raw_udp_data_loop()
{
	TRACE_func_entry();

	while (true)
	{
		auto data = raw_udp_data_->dequeue();

		if (data->empty()) break;

		usrsctp_conninput(this, data->data(), data->size(), /* ecn_bits */ 0);		
	}

	TRACE_func_left();
}



void ClientImpl::handle_server_data(void* buffer, ssize_t n, const struct sockaddr_in& addr,
					 const struct sctp_recvv_rn& rcv_info, unsigned int infotype)
{
	TRACE(state_names[state_]);

	size_t outbuf_len = (state_ != Client::State::SSL_CONNECTED) ?
								MAX_TLS_RECORD_SIZE : n;

	decrypted_msg_buff_.clear();
	decrypted_msg_buff_.resize(outbuf_len);
	void* outbuf = decrypted_msg_buff_.data();

	switch (state_) {
	case Client::State::SSL_HANDSHAKING:
	{

		int written = BIO_write(input_bio_, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(ssl_, written)) throw std::runtime_error("SSL_write");

		int res = SSL_do_handshake(ssl_);

		if (not SSL_is_init_finished(ssl_)) {
			if (SSL_ERROR_WANT_READ == SSL_get_error(ssl_, res) and BIO_ctrl_pending(output_bio_)) {
				int read = BIO_read(output_bio_, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl_, read)) {
					throw std::runtime_error("BIO_read");
				}
				if (send_raw(outbuf, read) < 0) {
					throw std::runtime_error(strerror(errno));
				}
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl_, res) and BIO_ctrl_pending(output_bio_)) {
				int read = BIO_read(output_bio_, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl_, read)) {
					throw std::runtime_error("BIO_read");
				}
				if (send_raw(outbuf, read) < 0) {
					throw std::runtime_error(strerror(errno));
				}

				state(Client::State::SSL_CONNECTED);
				break;
			}

			if (SSL_ERROR_NONE == SSL_get_error(ssl_, res) and !BIO_ctrl_pending(output_bio_)) {
				state(Client::State::SSL_CONNECTED);
				break;
			}

		} else {
			if (BIO_ctrl_pending(output_bio_)) {
				int read = BIO_read(output_bio_, outbuf, outbuf_len);
				if (SSL_ERROR_NONE != SSL_get_error(ssl_, read)) throw std::runtime_error("BIO_read");

				if (send_raw(outbuf, read) < 0) throw std::runtime_error(strerror(errno));
			}

			state(Client::State::SSL_CONNECTED);
		}
	}
	break;

	case Client::State::SSL_CONNECTED:
	{
		TRACE(std::string("encrypted message length n: ") + std::to_string(n));

		int written = BIO_write(input_bio_, buffer, n);
		if (SSL_ERROR_NONE != SSL_get_error(ssl_, written)) {
			throw std::runtime_error("BIO_write");
		}

		size_t total_decrypted_message_size = 0;
		int read = -1;

		while (BIO_ctrl_pending(input_bio_)) {
			read = SSL_read(ssl_, static_cast<char*>(outbuf) + total_decrypted_message_size, MAX_TLS_RECORD_SIZE);
			TRACE(std::string("SSL read: ") + std::to_string(read));

			if (read == 0 and (SSL_ERROR_ZERO_RETURN == SSL_get_error(ssl_, read))) {
				state(Client::State::SSL_SHUTDOWN);
				break;
			}

			if (read < 0 and (SSL_ERROR_WANT_READ == SSL_get_error(ssl_, read))) {
				TRACE("SSL_ERROR_WANT_READ");
				continue;
			}

			BOOST_ASSERT(SSL_ERROR_NONE == SSL_get_error(ssl_, read));

			total_decrypted_message_size += read;
		}

		if (read > 0) DEBUG(([&]
		{
			char message[BUFFERSIZE] = {'\0'};
			char name[INET_ADDRSTRLEN];

			if (infotype == SCTP_RECVV_RCVINFO)
			{
				snprintf(message, sizeof message,
							"Msg %s of length %llu received from %s:%u on stream %u with SSN %u and TSN %u, PPID %u, context %u.\n",
							(char*) outbuf,
							(unsigned long long) total_decrypted_message_size,
							inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN), ntohs(addr.sin_port),
							rcv_info.recvv_rcvinfo.rcv_sid,	rcv_info.recvv_rcvinfo.rcv_ssn,	rcv_info.recvv_rcvinfo.rcv_tsn,
							ntohl(rcv_info.recvv_rcvinfo.rcv_ppid), rcv_info.recvv_rcvinfo.rcv_context);
			}
			else
			{
				if (n < 30) snprintf(message, sizeof message, "Msg %s of length %llu received from %s:%u",
						(char*) outbuf,
						(unsigned long long) total_decrypted_message_size,
						inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
						ntohs(addr.sin_port));
				else snprintf(message, sizeof message, "Msg of length %llu received from %s:%u",
						(unsigned long long) total_decrypted_message_size,
						inet_ntop(AF_INET, &addr.sin_addr, name, INET_ADDRSTRLEN),
						ntohs(addr.sin_port));
			}

			return std::string(message);
		})());

		if (cfg_->data_cback_f and (read > 0))
		{
			// std::unique_ptr<sctp::Data> data;

			// try
			// {
			// 	data = std::make_unique<sctp::Data>(outbuf, total_decrypted_message_size);
			// }
			// catch (std::runtime_error& exc)
			// {
			// 	ERROR(exc.what());
			// 	break;
			// }
			
			try
			{
				//cfg_->data_cback_f(std::move(data));
				cfg_->data_cback_f(std::make_unique<std::vector<char>>(static_cast<char*>(outbuf), static_cast<char*>(outbuf)+total_decrypted_message_size));
			}
			catch (...)
			{
				CRITICAL("Exception in user data_cback function.");
			}
		}
	}
	break;

	case Client::State::SCTP_CONNECTED:
	default:
		throw std::logic_error("Received data in unhandled client state.");
		break;
	}
}



void ClientImpl::handle_association_change_event(struct sctp_assoc_change* sac)
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

		message += ".";//\n";

		return message;
	})();
	DEBUG(message);

	/*
		Real association change handling
	*/
	switch (sac->sac_state) {
	case SCTP_COMM_UP:
		state(Client::State::SCTP_CONNECTED);
		state(Client::State::SSL_HANDSHAKING);
		break;

	case SCTP_COMM_LOST:
		break;

	case SCTP_RESTART:
		break;

	case SCTP_SHUTDOWN_COMP:

		break;

	case SCTP_CANT_STR_ASSOC:
		break;
	default:
		break;
	}

	return;
}

void ClientImpl::handle_shutdown_event(struct sctp_shutdown_event*)
{
	char buf[BUFFERSIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Shutdown event.\n");
	DEBUG(buf);
	/* XXX: notify all channels. */
	return;
}

void ClientImpl::handle_peer_address_change_event(struct sctp_paddr_change* spc)
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

void ClientImpl::handle_send_failed_event(struct sctp_send_failed_event* ssfe)
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

void ClientImpl::handle_adaptation_indication(struct sctp_adaptation_event* sai)
{
	char buf[BUFFERSIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Adaptation indication: %x.\n", sai-> sai_adaptation_ind);
	DEBUG(buf);
	return;
}

void ClientImpl::handle_stream_reset_event(struct sctp_stream_reset_event* strrst)
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

void ClientImpl::handle_stream_change_event(struct sctp_stream_change_event* strchg)
{
	char buf[BUFFERSIZE] = { '\0' };
	snprintf(buf, sizeof buf, "Stream change event: streams (in/out) = (%u/%u), flags = %x.\n",
	       strchg->strchange_instrms, strchg->strchange_outstrms, strchg->strchange_flags);
	DEBUG(buf);

	return;
}

void ClientImpl::handle_remote_error_event(struct sctp_remote_error* sre)
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

void ClientImpl::handle_sender_dry_event(struct sctp_sender_dry_event*)
{
	*sender_dry_ptr_ = true;

	if (state_ == Client::State::SSL_CONNECTED and cfg_->send_possible_cback_f) {
		try {
			cfg_->send_possible_cback_f();
		} catch (...) {
			CRITICAL("Exception in user send_possible_cback function.");
		}
	}	
}

void ClientImpl::handle_notification(union sctp_notification* notif, size_t n)
{
	if (notif->sn_header.sn_length != (uint32_t) n) {
		WARNING("notif->sn_header.sn_length != n");
		return;
	}

	TRACE("handle_notification: " + notification_names[notif->sn_header.sn_type]);

	switch (notif->sn_header.sn_type) {
	case SCTP_ASSOC_CHANGE:
		handle_association_change_event(&(notif->sn_assoc_change));
		break;
	case SCTP_PEER_ADDR_CHANGE:
		handle_peer_address_change_event(&(notif->sn_paddr_change));
		break;
	case SCTP_REMOTE_ERROR:
		handle_remote_error_event(&(notif->sn_remote_error));
		break;
	case SCTP_SHUTDOWN_EVENT:
		handle_shutdown_event(&(notif->sn_shutdown_event));
		break;
	case SCTP_ADAPTATION_INDICATION:
		handle_adaptation_indication(&(notif->sn_adaptation_event));
		break;
	case SCTP_PARTIAL_DELIVERY_EVENT:
		break;
	case SCTP_AUTHENTICATION_EVENT:
		break;
	case SCTP_SENDER_DRY_EVENT:
		handle_sender_dry_event(&(notif->sn_sender_dry_event));
		break;
	case SCTP_NOTIFICATIONS_STOPPED_EVENT:
		break;
	case SCTP_SEND_FAILED_EVENT:
		handle_send_failed_event(&(notif->sn_send_failed_event));
		break;
	case SCTP_STREAM_RESET_EVENT:
		handle_stream_reset_event(&(notif->sn_strreset_event));
		break;
	case SCTP_ASSOC_RESET_EVENT:
		break;
	case SCTP_STREAM_CHANGE_EVENT:
		handle_stream_change_event(&(notif->sn_strchange_event));
		break;
	default:
		break;
	}
}

} //namespace sctp
