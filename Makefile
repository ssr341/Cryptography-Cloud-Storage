all: clientFiles/client serverFiles/server
#Put CAFiles/CA after serverFiles/server to compile CA

clientFiles/client: clientFiles/client.cpp utility.cpp
	g++ -std=c++11 -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o clientFiles/client clientFiles/client.cpp utility.cpp -lcryptopp

serverFiles/server: serverFiles/server.cpp utility.cpp
	g++ -std=c++11 -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o serverFiles/server serverFiles/server.cpp utility.cpp -lcryptopp

#CAFiles/CA: CAFiles/CA.cpp utility.cpp
#	g++ -std=c++11 -g3 -ggdb -O0 -Wall -Wextra -Wno-unused -o CAFiles/CA CAFiles/CA.cpp utility.cpp -lcryptopp