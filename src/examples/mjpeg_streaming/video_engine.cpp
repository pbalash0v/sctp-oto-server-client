#include "video_engine.h"
#include "spdlog/spdlog.h"


namespace
{
	void set_thread_name(std::thread& thread, const char* name)
	{
	   auto handle = thread.native_handle();
	   pthread_setname_np(handle, name);
	}
}


VideoEngine::VideoEngine()
{
	if (!camera.isOpened()) {
		throw std::runtime_error("Could not open camera.");
	}

	capture_thread = std::thread { &VideoEngine::capture_loop, this };
	local_display_thread = std::thread { &VideoEngine::local_display_loop, this };

	cv::namedWindow("Webcam", cv::WINDOW_AUTOSIZE);
	cv::namedWindow("Echo", cv::WINDOW_AUTOSIZE);
}

VideoEngine::~VideoEngine()
{
	running = false;
	recvd_data.enqueue(std::make_unique<sctp::Data>());

	if (capture_thread.joinable()) capture_thread.join();
	if (local_display_thread.joinable()) local_display_thread.join();
	if (local_encode_thread.joinable()) local_encode_thread.join();
	if (send_thread.joinable()) send_thread.join();
	if (recvd_decode_thread.joinable()) recvd_decode_thread.join();
	if (recvd_display_thread.joinable()) recvd_display_thread.join();
}


void VideoEngine::put_frame_data(std::unique_ptr<sctp::Data> frame_data)
{
	recvd_data.enqueue(std::move(frame_data));
}


void VideoEngine::operator()(SCTPClient& oth)
{
	local_encode_thread = std::thread { &VideoEngine::encode_loop, this };
	send_thread = std::thread { &VideoEngine::send_loop, this, std::ref(oth)};
	recvd_decode_thread = std::thread { &VideoEngine::decode_loop, this };
	recvd_display_thread = std::thread{ &VideoEngine::recvd_display_loop, this };

	set_thread_name(local_encode_thread, "mjpeg_encoder");
	set_thread_name(recvd_decode_thread, "mjpeg_decoder");
	set_thread_name(send_thread, "sender");
	set_thread_name(capture_thread, "cam_capturer");
}


void VideoEngine::capture_loop()
{
	spdlog::debug("{} started.", __func__);

	while (running) {
		auto frame_ptr = std::make_shared<cv::Mat>();

		// capture the next frame from the webcam
		camera.read(*frame_ptr);

		local_frames_to_display.enqueue(frame_ptr);
		frames_to_encode.enqueue(frame_ptr);
	}

	auto null_frame_ptr = std::make_shared<cv::Mat>();
	local_frames_to_display.enqueue(null_frame_ptr);
	frames_to_encode.enqueue(null_frame_ptr);

	spdlog::debug("{} finished.", __func__);
}


void VideoEngine::local_display_loop()
{
	spdlog::debug("{} started.", __func__);

	do {
		auto frame = *(local_frames_to_display.dequeue());

		if (frame.empty()) break;

		// show the image on the window
		cv::imshow("Webcam", frame);
		
		// wait (10ms) for a key to be pressed
		cv::waitKey(10);
	} while (true);

	spdlog::debug("{} finished.", __func__);
}


void VideoEngine::encode_loop()
{
	spdlog::debug("{} started.", __func__);

	do {
		auto frame = *(frames_to_encode.dequeue());

		if (frame.empty()) break;

		auto jpeg_ptr = std::make_shared<std::vector<uchar>>();

		cv::imencode(".jpg", frame, *jpeg_ptr);

		frames_to_send.enqueue(jpeg_ptr);
	} while (true);

	auto empty_jpeg_ptr = std::make_shared<std::vector<uchar>>();
	frames_to_send.enqueue(empty_jpeg_ptr);

	spdlog::debug("{} finished.", __func__);
}


void VideoEngine::send_loop(SCTPClient& client)
{
	spdlog::debug("{} started.", __func__);

	do {
		auto jpeg = *(frames_to_send.dequeue());

		if (jpeg.size() == 0) break;
		try {
			client.send(jpeg.data(), jpeg.size());
		} catch (std::runtime_error& exc) {
			spdlog::warn("Send failed: {}.", exc.what());
		}
	} while (true);

	spdlog::debug("{} finished.", __func__);
}


void VideoEngine::decode_loop()
{
	spdlog::debug("{} started.", __func__);

	do {
		auto data = recvd_data.dequeue();

		if (data->size == 0) break;

		auto jpeg = cv::Mat(1, data->size, CV_8UC1, data->buf);

		auto mat_ptr = std::make_unique<cv::Mat>(cv::imdecode(jpeg, CV_LOAD_IMAGE_UNCHANGED));
		
		recvd_frames_to_display.enqueue(std::move(mat_ptr));
	} while (true);

	auto empty_frame_ptr = std::make_unique<cv::Mat>();
	recvd_frames_to_display.enqueue(std::move(empty_frame_ptr));

	spdlog::debug("{} finished.", __func__);
}


void VideoEngine::recvd_display_loop()
{
	spdlog::debug("{} started.", __func__);

	do {
		auto frame = recvd_frames_to_display.dequeue();

		if (frame->empty()) break;

		// show the image on the window
		cv::imshow("Echo", *frame);
		
		// wait (10ms) for a key to be pressed
		cv::waitKey(10);
	} while (true);

	spdlog::debug("{} finished.", __func__);
}