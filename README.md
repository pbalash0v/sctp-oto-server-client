# Simple one-to-one style TLS SCTP Server and Client
(mainly for educational purposes, WiP)

Clone this repository using:
```console
git clone https://github.com/pbalash0v/sctp-oto-server-client.git --recurse-submodules
```
(please make sure to add --recurse-submodules as this is necessary for pulling dependencies)

To compile and run you may need to install some prerequisite packages.
On a debian-base distribution:
```console
apt install autoconf libtool build-essential libssl-dev pkg-config 
```

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
