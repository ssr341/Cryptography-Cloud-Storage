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
#include "../utility.h"
using namespace std;
using namespace CryptoPP;

#define PORT 1111

int main() {
  /*
  //Used to generate keys
  
  string CA1("../CAFiles/"); CA1.append(computeHash("myKey"));
  string CA2("../CAFiles/"); CA2.append(computeHash("clientKey"));
  string CA3("../CAFiles/"); CA3.append(computeHash("serverKey"));
  string CA4("../CAFiles/"); CA4.append(computeHash("CAKey"));
  string client1("../clientFiles/"); client1.append(computeHash("myKey"));
  string client2("../clientFiles/"); client2.append(computeHash("CAKey"));
  string server1("../serverFiles/"); server1.append(computeHash("myKey"));
  string server2("../serverFiles/"); server2.append(computeHash("CAKey"));
  RSAKeys CAKeys = genRSAKeys();
  saveRSAPubKey(*(CAKeys.publicKey), CA4.c_str());
  saveRSAPubKey(*(CAKeys.publicKey), client2.c_str());
  saveRSAPubKey(*(CAKeys.publicKey), server2.c_str());
  saveRSAPriKey(*(CAKeys.privateKey), CA1.c_str());
  RSAKeys clientKeys = genRSAKeys();
  saveRSAPubKey(*(clientKeys.publicKey), CA2.c_str());
  saveRSAPriKey(*(clientKeys.privateKey), client1.c_str());
  RSAKeys serverKeys = genRSAKeys();
  saveRSAPubKey(*(serverKeys.publicKey), CA3.c_str());
  saveRSAPriKey(*(serverKeys.privateKey), server1.c_str());
  */
  

  //Create socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) { perror("Faield to create socket fd"); }

  struct sockaddr_in sockaddr;
  memset(&sockaddr, 0, sizeof(sockaddr));
  sockaddr.sin_family = AF_INET;
  sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  sockaddr.sin_port = htons(PORT);

  //Bind address to socket
  if (bind(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) == -1) {
    perror("Failed to bind sockaddr to socket fd");
  }

  //Put socket in passive mode
  if (listen(sockfd, BACKLOG) == -1) {
    perror("Failed to mark socket as a passive socket");
  }

  while (1) {
    cout << "Waiting for connection" << endl;
    //Accept a connection
    int fd = accept(sockfd, NULL, NULL);
    if (fd == -1) { perror("Failed to accept connection"); }
    else { printf("Successfully connected to client\n"); }
    
    string message = rcvRSAData(fd);
    cout << message << endl;

    istringstream iss(message);
    string sender;
    string keyNeeded;
    iss >> sender >> keyNeeded;
    sendPublicKey(fd, keyNeeded, "CA", sender);

  }

  /*
  Test code
  while (1) {
    char buf[BUF_SIZE];

    string fileString;
    int result = prompt(fileString);
    if (result == 3)
      repeat = false;
    // hash a file, encrypt it and save it
    else if (result == 1){
      const char* fileName = fileString.c_str();
      fstream file(computeHash(fileName));
      if (file) {
        string data;
        getline(file, data, (char)file.eof());
        //file.clear();
        addHash(data);
        // encrypt
        string newFileName = fileName;
        newFileName.append("_encrypt");
        fstream encryptedFile(computeHash(newFileName), fstream::out | fstream::binary);
        AESParams params = genAESParams();
        AESEncrypt(params.key, params.iv, data, encryptedFile);
        encryptedFile.close();
      }
      else
        cout << "Not a valid file name.\n";
      file.close();
    }
    // decrypt a file. store its hash. output it. check hash of output
    else if (result == 2) {
      string fileName = fileString;
      fileName.append("_encrypt");
      fstream file(computeHash(fileName), fstream::in | fstream::binary);
      if (file) {
        // store file's contents into string to be decrypted
        string encryption;
        getline(file, encryption, (char)file.eof());
        ifstream ifs("KeyAndIV");
        string key;
        string iv;
        ifs >> key >> iv;
        string keyString = htos(key);
        string ivString = htos(iv);
        AESDecrypt(keyString, ivString, encryption);
      }
      else
        cout << "Not a valid file name.\n";
      file.close();
    }
  }
  */
}