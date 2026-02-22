all:
	g++ -I/usr/include/openssl/ main.cpp -o main -lcrypto -w
debug:
	g++ -fsanitize=address -I/usr/include/openssl/ main.cpp -g -o main -lcrypto -w -lssl -lpthread
