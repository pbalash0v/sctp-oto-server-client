#pragma once


#ifndef NDEBUG
#define log(level, text) \
						do { \
							if (nullptr == cfg_->debug_cback_f) break; \
							std::string s = std::string(); \
							s += std::string(basename(__FILE__)) + \
							 + ", " + std::string(__func__) + \
							 + ":" + std::to_string(__LINE__) + \
							 + "\t " + std::string(text); \
								cfg_->debug_cback_f(level, s); \
						} while (0)

#define CHECK_STATE() \
						do { \
							if (not (_check_state(std::string(__func__), state_))) { \
								CRITICAL("Wrong state transition."); \
								throw std::logic_error("Disallowed state."); \
							} \
						} while (0)

#else
#define log(level, text) do {} while (0)
#define CHECK_STATE() do {} while (0)
#endif

#define TRACE(text) log(sctp::TRACE, text)
#define DEBUG(text) log(sctp::DEBUG, text)
#define INFO(text) log(sctp::INFO, text)
#define WARNING(text) log(sctp::WARNING, text)
#define ERROR(text) log(sctp::ERROR, text)
#define CRITICAL(text) log(sctp::CRITICAL, text)

#define TRACE_func_entry() TRACE("Entered " + std::string(__func__))
#define TRACE_func_left() TRACE("Left " + std::string(__func__))