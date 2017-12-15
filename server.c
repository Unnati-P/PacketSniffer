#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(){
  int servSocket, newSocket;
  char buffer[1024];
  struct sockaddr_in serverAddr;
  struct sockaddr_storage serverStorage;
  socklen_t addr_size;

  /*---- Create the socket. The three arguments are: ----*/
  /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
  servSocket = socket(PF_INET, SOCK_STREAM, 0);
  
  /*---- Configure settings of the server address struct ----*/
  /* Address family = Internet */
  serverAddr.sin_family = AF_INET;
  /* Set port number, using htons function to use proper byte order */
  serverAddr.sin_port = htons(7891);
  /* Set IP address to localhost */
  serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  /* Set all bits of the padding field to 0 */
  memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

  /*---- Bind the address struct to the socket ----*/
  bind(servSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

  /*---- Listen on the socket, with 5 max connection requests queued ----*/
  if(listen(servSocket,5)==0)
    printf("Listening\n");
  else
    printf("Error\n");

  /*---- Accept call creates a new socket for the incoming connection ----*/
  addr_size = sizeof serverStorage;
  newSocket = accept(servSocket, (struct sockaddr *) &serverStorage, &addr_size);

  recv(newSocket,buffer,1024,0);
	printf("%s\n", buffer);
  if(strcmp(buffer,"ON_AN_ATTACK")) {
	strcpy(buffer,"START");
        send(newSocket,buffer,6,0);
  }

/*	int buf[100][256];
	int i=0, j=0;
	while(1){
	recv(newSocket,buf,100*256,0);
	for(i=0; i<100 ;i ++) {
		for(j=0; j<256; j++) {
			if(buf[i][j])
				printf("%d\n",buf[i][j]);
			else
				break;
	}
	}
	}*/


  return 0;
}
