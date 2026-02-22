all:
	g++ -I/usr/include/openssl/ main.cpp -o main -lcrypto -lssl -lpthread -lrt -w
debug:
	g++ -fsanitize=address -I/usr/include/openssl/ main.cpp -g -o main -lcrypto -lssl -lpthread -lrt -w
