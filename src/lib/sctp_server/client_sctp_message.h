#pragma once

struct SCTPMessage
{
	SCTPMessage(const void*, size_t);
	SCTPMessage(const SCTPMessage& oth) = delete;
	SCTPMessage& operator=(const SCTPMessage& oth) = delete;

	virtual ~SCTPMessage();

	void* data { nullptr };
	size_t size { 0 };
};

