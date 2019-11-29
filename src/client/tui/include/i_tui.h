#pragma once

#include <string>
#include <functional>


using ITUI_cback_t = std::function<void(const std::string&)>;

class ITUI {
public:
	virtual void init(ITUI_cback_t cback) = 0;

	virtual void loop() = 0; 

	virtual void put_message(const std::string&) = 0;

	virtual void stop() = 0;
	
	virtual ~ITUI() {};
};	
