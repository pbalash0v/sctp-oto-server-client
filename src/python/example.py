#!/usr/bin/env python3

import sys
import pysctp


def on_log(level, msg):
	print("[{}] {} ".format(level.name, msg))

def on_event(evt):
	print("Got server event {}".format(evt))

def main():
	cfg = pysctp.ServerConfig()
	cfg.debug_cback = on_log
	cfg.event_cback = on_event
	server = pysctp.Server(cfg)
	server()

	while True:
		if not (sys.stdin.readline()):
			server.stop()
			return


if __name__ == '__main__':
	main()