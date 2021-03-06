# Simple one-to-one style SCTP TLS Server and Client
(mainly for educational purposes, WiP)

To compile and run you may need to install some prerequisite packages.
On a debian-base distribution:
```console
apt install libboost-dev libboost-filesystem-dev libboost-system-dev build-essential libssl-dev pkg-config 
```

To build:
```console
mkdir sctp_oto && cd sctp_oto
git clone https://github.com/pbalash0v/sctp-oto-server-client.git sctp-oto-server-client.git
mkdir build-Debug && cd build-Debug
cmake ../sctp-oto-server-client.git
cmake --build .
```

---  
Broadcast server will retranslate any message received to all connected clients, adhering to stop-and-wait flow control policy.
To run broadcast server (from **build** directory, in separate shell or tmux, terminate server with ctrl-d):
```console
out/bin/broadcast_server -v
```
To run client(s) (from **build** directory, in separate shell or tmux, terminate client with ctrl-d):
```console
out/bin/broadcast_client
```

---  
Discard client will send random messages ranging from 1 to 65535 bytes, adhering to stop-and-wait flow control policy.
To run discard server (from **build** directory, in separate shell or tmux, terminate server with ctrl-d):
```console
out/bin/discard_server -v
```
To run discard client(s) (from **build** directory, in separate shell or tmux, terminate client with ctrl-d):
```console
out/bin/discard_client
```

---
Some rudimentary tests ( from **build** directory):
```console
ctest
```
