#pragma once

#include <string>
#include <functional>


using ITUI_cback_t = std::function<void(const std::string&)>;

class ITUI
{
public:
   enum LogLevel
   {
   	TRACE,
      DEBUG,
      INFO,
      WARNING,
      ERROR,
		CRITICAL
   };

	virtual void init(ITUI_cback_t cback) = 0;

	virtual void loop() = 0; 

	virtual void put_message(const std::string&) = 0;

	virtual void put_log(ITUI::LogLevel, const std::string&) = 0;

	virtual void set_log_level(ITUI::LogLevel) = 0;

	virtual void stop() = 0;

	virtual ~ITUI() {};
};	
