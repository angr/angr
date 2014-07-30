#include <stdio.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>


//######
//Read from a socket to the int, then increment the int, then write it out to the socket
//######
int main(void)
{
	int sockfd, newsockfd, portno, clilen,n;
	int readme = 8;
	int checkit, num;
	char buf[3] = "hi";
	char store_buf[4];
	
	char key[4] = "fun";
	
	
	struct sockaddr_in serv_addr, cli_addr;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	portno = 8000;
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);
	bind(sockfd, (struct sockaddr *) &serv_addr,sizeof(serv_addr));
		
	listen(sockfd,0);
	
	
	
	newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	
	send(newsockfd, buf, 3, 0);
	
	recv(sockfd, store_buf, 4, 0);
	
	if (strcmp(store_buf, key) == 0)
		printf("winner\n");
	

	return 0;
}