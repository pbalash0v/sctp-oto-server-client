#pragma once

#include "opencv2/opencv.hpp"
#include "sync_queue.hpp"
#include "sctp_client.h"



class VideoEngine
{
public:
	explicit VideoEngine();
	VideoEngine(const VideoEngine&) = delete;
	VideoEngine& operator=(const VideoEngine&) = delete;
	virtual ~VideoEngine();

	void operator()(SCTPClient&);

	void put_frame_data(std::unique_ptr<sctp::Data>);

private:
	std::atomic_bool running { true };

	// queues for local data
	SyncQueue<std::shared_ptr<cv::Mat>> local_frames_to_display;
	SyncQueue<std::shared_ptr<cv::Mat>> frames_to_encode;
	SyncQueue<std::shared_ptr<std::vector<uchar>>> frames_to_send {/* max queued */ 5};

	// queues for remote data
	SyncQueue<std::unique_ptr<sctp::Data>> recvd_data;
	SyncQueue<std::unique_ptr<cv::Mat>> recvd_frames_to_display;

	cv::VideoCapture camera { 0 };

	std::thread capture_thread;
	std::thread local_display_thread;
	std::thread local_encode_thread;
	std::thread send_thread;
	std::thread recvd_decode_thread;
	std::thread recvd_display_thread;

	void capture_loop();
	void local_display_loop();
	void encode_loop();
	void send_loop(SCTPClient&);
	void decode_loop();
	void recvd_display_loop();
};