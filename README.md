# Simple implementation of one-to-one style TLS SCTP Server and Client
(mainly for educational purposes, WiP)

Clone this repository using:
```console
git clone https://github.com/pbalash0v/sctp-oto-server-client.git --recurse-submodules
```
(please make sure to add --recurse-submodules as this is necessary for pulling dependencies)

To compile and run you need to have build essentials, libssl-dev and autotools installed.
(Debian 8 [needs clang++ for C++14 support], Debian 9 and Ubuntu 18 has been tested).

To build (from **cloned repository** directory):
```console
autoreconf -fi
mkdir build
cd build
../configure
make 
```

To run broadcast server (from **build** directory, in separate shell or tmux, terminate server with ctrl-d):
```console
cd src/examples/broadcast
./server -v
```

To run client(s) (from **build** directory, in separate shell or tmux, terminate client with ctrl-d):
```console
cd src/examples/broadcast
	./client
```


Some rudimentary tests ( from **build** directory):
```console
make check
```
