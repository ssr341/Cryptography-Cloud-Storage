#include "crypto++/cryptlib.h"
#include "crypto++/rsa.h"
#include "crypto++/sha.h"
#include "crypto++/hex.h"
#include "crypto++/aes.h"
#include "crypto++/modes.h"
#include "crypto++/filters.h"
#include "crypto++/osrng.h"
#include "crypto++/files.h"
#include "crypto++/base64.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "stdlib.h"
#include "../utility.h"
using namespace std;
using namespace CryptoPP;

int main() {
  //Get server public key from CA
  //getPublicKey("serverKey", "127.0.0.1", 1111);
  /*
  AESParams aesParams = genAESParams();
  ofstream ofs(computeHash("KeyAndIV"));
  string keyString = btoh(aesParams.key);
  string ivString = btoh(aesParams.iv);
  ofs << keyString << endl << ivString;
  ofs.close();
  */

  char dest[BUF_SIZE];
  fprintf(stderr, "Please enter the destination IP address: ");
  getInput(dest, BUF_SIZE);
  fprintf(stderr, "Please enter the destination port number: ");
  int port = getPortNum();

  //Create socket
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == -1) { perror("Failed to create socket fd"); }

  //Create sockaddr_in to store socket information
  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;

  //Convert dotted decimal address to network address structure and place in sockaddr
  int res = inet_pton(AF_INET, dest, &sockaddr.sin_addr);
  if (res == 0) { perror("Invalid network address"); }
  if (res == -1) { perror("Invalid address family"); }

  //Specify port used to connect to server
  sockaddr.sin_port = htons(port);

  //Connect to the server
  if (connect(fd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1) {
    perror("Failed to connect to server");
  }
  else { printf("Successfully connected to server\n"); }

  while(1){
    string message;
    string file;
    int response = prompt(file);
    string buf = to_string(response);
    //char buf[BUF_SIZE];
    //itoa(response, buf, 10);
    message.append(buf);
    message.append("\n");

    if (response == 3) break;
    else if (response == 1) {
      message.append(file);
      message.append("\n");

      string fileData;
      ifstream ifs(file);
      getline(ifs, fileData, (char)ifs.eof());
      message.append(fileData);
      ifs.close();

      ifs.open(computeHash("KeyAndIV"));
      string keyString;
      string ivString;
      ifs >> keyString >> ivString;
      ifs.close();
      keyString = htos(keyString);
      ivString = htos(ivString);

      SecByteBlock key((byte *)keyString.data(), keyString.size()); 
      SecByteBlock iv((byte *)ivString.data(), ivString.size());

      string cipher = AESEncrypt(key, iv, message);
      string message = btoh(cipher);
      cout << message << endl;
      write(fd, cipher.c_str(), cipher.length());
    }
  }
}