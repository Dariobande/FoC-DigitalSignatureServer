# Primary make rule with dummy target 'all' --> does not create any 'all' file but triggers full build
# It depends on the targets client and server defined below
all: client server

# Rule for building the client
client: src/client.o src/utils.o
	g++ -Wall src/client.o src/utils.o -o client -lcrypto

src/client.o: src/client.cpp include/utils.hpp
	g++ -Wall -c src/client.cpp -o src/client.o

# Rule for building the server
server: src/server.o src/utils.o
	g++ -Wall src/server.o src/utils.o -o server -lcrypto

src/server.o: src/server.cpp include/utils.hpp
	g++ -Wall -c src/server.cpp -o src/server.o

# Rule for building utils (shared by client and server)
src/utils.o: src/utils.cpp include/utils.hpp
	g++ -Wall -c src/utils.cpp -o src/utils.o

# Clean up compilation files (executed by running 'make clean' in terminal)
clean:
	rm -f src/*.o client server

