#pragma once

#include <vector>


class RandGen
{
public:
	RandGen();
	RandGen(const RandGen&) = delete;
	RandGen& operator=(const RandGen&) = delete;
	std::vector<char> operator()();
	virtual ~RandGen();
private:
	int urandom_fd_;
};