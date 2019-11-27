certs = client-key.pem server-key.pem
				
##				client-cert.pem \
##				server-cert.pem \
				
all: $(certs)
				
client-key.pem:
	openssl req -batch -x509 -newkey rsa:2048 -days 3650 -nodes -keyout $@ -out $(subst key,cert,$@)
				
server-key.pem:
	openssl req -batch -x509 -newkey rsa:2048 -days 3650 -nodes -keyout $@ -out $(subst key,cert,$@)				

 
CLEANFILES = client-key.pem server-key.pem client-cert.pem server-cert.pem
