#ifndef __log_level_hpp__
#define __log_level_hpp__

namespace sctp
{

enum class LogLevel
{
	TRACE,
	DEBUG,
	INFO,
	WARNING,
	ERROR,
	CRITICAL,
	NONE
};

} //namespace sctp

#endif // __log_level_hpp__