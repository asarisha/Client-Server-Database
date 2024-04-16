#include <arpa/inet.h>
#include <assert.h>
#include <errno.h> 
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <inttypes.h>

#include "msg.h"

#define BUF 256

void Usage(char *progname);

int put(int socket_fd);

int get(int socket_fd);

int LookupName(char *name,
                unsigned short port,
                struct sockaddr_storage *ret_addr,
                size_t *ret_addrlen);

int Connect(const struct sockaddr_storage *addr,
             const size_t addrlen,
             int *ret_fd);

int 
main(int argc, char **argv) {
  if (argc != 3) {
    Usage(argv[0]);
  }

  unsigned short port = 0;
  if (sscanf(argv[2], "%hu", &port) != 1) {
    Usage(argv[0]);
  }

  // Get an appropriate sockaddr structure.
  struct sockaddr_storage addr;
  size_t addrlen;
  if (!LookupName(argv[1], port, &addr, &addrlen)) {
    Usage(argv[0]);
  }

  // Connect to the remote host.
  int socket_fd;
  if (!Connect(&addr, addrlen, &socket_fd)) {
    Usage(argv[0]);
  }
  
  //prompt the user to choose an operation
  int8_t choice = 0;
  int cont = 1;
  while(cont) {
    printf("Enter your choice (1 to put, 2 to get, 0 to quit): ");
	  scanf("%" SCNd8 "%*c", &choice);
     switch (choice){
		case PUT: 
			if(!put(socket_fd)) return EXIT_FAILURE;
			break;
		case GET:
     if(!get(socket_fd)) return EXIT_FAILURE;
			break;
		default:
			cont = 0;
	}
  }
   
  // Clean up.
  close(socket_fd);
  return EXIT_SUCCESS;
}  
int
put(int socket_fd) {
  struct record rd;
      //prompt the user for the name and store in record
      printf("Enter the name: ");
      fgets(rd.name, MAX_NAME_LENGTH+1, stdin);
      int len = strlen(rd.name);
      rd.name[len - 1] = '\0';
      //prompt the user for the id and store in record
      printf("Enter the id: ");
      scanf("%d", &(rd.id));
      //create an appropriate message to send and copy it to buffer
      struct msg toServer = {PUT, rd};
      char* buf[260];
      memcpy(buf, &toServer, sizeof(buf));
      //write message to server
      int wres = write(socket_fd, buf, sizeof(buf));
      if (wres == 0) {
         printf("socket closed prematurely \n");
        close(socket_fd);
        return -1;
      }
      if (wres == -1) {
      if (errno != EINTR) {
        printf("socket write failure \n");
        close(socket_fd);
        return -1;
        }
      } 
      
      //read response from server
      struct msg fromServer;
      char* returnBuf[260];
      int res = read(socket_fd, returnBuf, sizeof(returnBuf));
      memcpy(&fromServer, buf, sizeof(fromServer));
      if (res == 0) {
      printf("socket closed prematurely \n");
      close(socket_fd);
      return -1;
      } 
      if (res == -1) {
      if (errno != EINTR) {
      printf("socket read failure \n");
      close(socket_fd);
      return -1;
      }
      }
      
      //print appropriate reponse
      if(fromServer.type == SUCCESS) {
        printf("Put success");
      }
      if(fromServer.type == FAIL) {
        printf("Put failed");
      }
      return 1;
}

int
get(int socket_fd) { 
    struct record rd;
    //prompt the user for the id and store in record
			printf("Enter the id: ");
      scanf("%d", &(rd.id));
      //create an appropriate message and copy it to buffer
      struct msg toServer = {GET, rd};
      char* buf[260];
      memcpy(buf, &toServer, sizeof(buf));
      //write message to server 
      int wres = write(socket_fd, buf, sizeof(buf));
      if (wres == 0) {
         printf("socket closed prematurely \n");
        close(socket_fd);
        return -1; 
      }
      if (wres == -1) {
      if (errno != EINTR) {
        printf("socket write failure \n");
        close(socket_fd);
      return -1;
      }
      }
      
      //read response from server
      struct msg fromServer;
      char* returnBuf[260];
      int res = read(socket_fd, returnBuf, sizeof(returnBuf));
      memcpy(&fromServer, buf, sizeof(fromServer));
      if (res == 0) {
      printf("socket closed prematurely \n");
      close(socket_fd);
      return -1;
      } 
      if (res == -1) {
      if (errno != EINTR) {
      printf("socket read failure \n");
      close(socket_fd);
      return -1;
      }
      }
      printf("message recieved");
      //print appropriate reponse
      if(fromServer.type == SUCCESS) {
        printf("Name: %s\nID: %u\n", fromServer.rd.name, fromServer.rd.id);
        printf("success");
      } 
      if(fromServer.type == FAIL) {
        printf("Get failed");
      }
      return 1;
}
void 
Usage(char *progname) {
  printf("usage: %s  hostname port \n", progname);
  exit(EXIT_FAILURE);
}

int 
LookupName(char *name,
                unsigned short port,
                struct sockaddr_storage *ret_addr,
                size_t *ret_addrlen) {
  struct addrinfo hints, *results;
  int retval;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  // Do the lookup by invoking getaddrinfo().
  if ((retval = getaddrinfo(name, NULL, &hints, &results)) != 0) {
    printf( "getaddrinfo failed: %s", gai_strerror(retval));
    return 0;
  }

  // Set the port in the first result.
  if (results->ai_family == AF_INET) {
    struct sockaddr_in *v4addr =
            (struct sockaddr_in *) (results->ai_addr);
    v4addr->sin_port = htons(port);
  } else if (results->ai_family == AF_INET6) {
    struct sockaddr_in6 *v6addr =
            (struct sockaddr_in6 *)(results->ai_addr);
    v6addr->sin6_port = htons(port);
  } else {
    printf("getaddrinfo failed to provide an IPv4 or IPv6 address \n");
    freeaddrinfo(results);
    return 0;
  }

  // Return the first result.
  assert(results != NULL);
  memcpy(ret_addr, results->ai_addr, results->ai_addrlen);
  *ret_addrlen = results->ai_addrlen;

  // Clean up.
  freeaddrinfo(results);
  return 1;
}

int 
Connect(const struct sockaddr_storage *addr,
             const size_t addrlen,
             int *ret_fd) {
  // Create the socket.
  int socket_fd = socket(addr->ss_family, SOCK_STREAM, 0);
  if (socket_fd == -1) {
    printf("socket() failed: %s", strerror(errno));
    return 0;
  }

  // Connect the socket to the remote host.
  int res = connect(socket_fd,
                    (const struct sockaddr *)(addr),
                    addrlen);
  if (res == -1) {
    printf("connect() failed: %s", strerror(errno));
    return 0;
  }

  *ret_fd = socket_fd;
  return 1;
}
