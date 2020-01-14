#pragma once

#include <chrono>
#include <ostream>

class TrafficStats
{
public:
	TrafficStats() = default;
	TrafficStats(const TrafficStats&) = delete;
	TrafficStats& operator=(const TrafficStats&) = delete;
	void update(size_t) noexcept;

	virtual ~TrafficStats() = default;

	friend std::ostream& operator<<(std::ostream&, const TrafficStats&);

private:
	std::chrono::time_point<std::chrono::system_clock> start { std::chrono::system_clock::now() };
	std::chrono::time_point<std::chrono::system_clock> end { std::chrono::system_clock::now() };
	size_t sent_total = 0;
};