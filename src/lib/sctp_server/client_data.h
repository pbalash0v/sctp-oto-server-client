#pragma once

struct Data
{
	Data(const void*, size_t);
	Data(const Data& oth) = delete;
	Data& operator=(const Data& oth) = delete;

	virtual ~Data();

	void* data { nullptr };
	size_t size { 0 };
};

