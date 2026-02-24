all:
	g++ -I/usr/include/openssl/ client.cpp -o client -lcrypto -lssl -lpthread -lrt -w
	g++ -I/usr/include/openssl/ server.cpp -g -o server -lcrypto -w -lssl -lpthread -lrt
debug:
	g++ -fsanitize=address -I/usr/include/openssl/ client.cpp -g -o client -lcrypto -lssl -lpthread -lrt -w
	g++ -fsanitize=address -I/usr/include/openssl/ server.cpp -g -o server -lcrypto -w -lssl -lpthread -lrt
