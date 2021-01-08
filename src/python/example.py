#!/usr/bin/env python3

import pyzrpc


def logger(level, msg):
	print("[{}]: {} ".format(level.name, msg))

def main():
	io_ctx = pyzrpc.IoContext()
	svc = pyzrpc.Service(io_ctx, "zrpc://pysvc:10101", logger, True)

	io_ctx.run()


if __name__ == '__main__':
	main()