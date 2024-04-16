#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/mman.h>
#include <pthread.h>
#include <assert.h>
#include <fcntl.h>
#include "common_threads.h"
#include "common.h"
#include "msg.h"

void Usage(char *progname);
void PrintOut(int fd, struct sockaddr *addr, size_t addrlen);
void PrintReverseDNS(struct sockaddr *addr, size_t addrlen);
void PrintServerSide(int client_fd, int sock_family);

int  Listen(char *portnum, int *sock_family);
void HandleClient(int c_fd);
void* handle(void *arg);
struct msg put(uint32_t, struct record);
struct msg get(uint32_t, struct record);

int
main(int argc, char **argv) {
  // Expect the port number as a command line argument.
  if (argc != 2) {
	Usage(argv[0]);
  }

  int sock_family;
  int listen_fd = Listen(argv[1], &sock_family);
  if (listen_fd <= 0) {
	// We failed to bind/listen to a socket.  Quit with failure.
	printf("Couldn't bind to any addresses.\n");
	return EXIT_FAILURE;
  }

  // Loop forever, accepting a connection from a client and doing
  // an echo trick to it.
  while (1) {
	struct sockaddr_storage caddr;
	socklen_t caddr_len = sizeof(caddr);
	int client_fd = accept(listen_fd,
                       	(struct sockaddr *)(&caddr),
                       	&caddr_len);
	if (client_fd < 0) {
  	if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK))
    	continue;
  	printf("Failure on accept:%s \n ", strerror(errno));
  	break;
	}

	/*HandleClient(client_fd,
             	(struct sockaddr *)(&caddr),
             	caddr_len,
             	sock_family);*/
	pthread_t clientThread;
	Pthread_create(&clientThread, NULL, handle, &client_fd);
	Pthread_join(clientThread, NULL);
  }

  // Close socket
  close(listen_fd);
  return EXIT_SUCCESS;
}

void Usage(char *progname) {
  printf("usage: %s port \n", progname);
  exit(EXIT_FAILURE);
}

void
PrintOut(int fd, struct sockaddr *addr, size_t addrlen) {
  printf("Socket [%d] is bound to: \n", fd);
  if (addr->sa_family == AF_INET) {
	// Print out the IPV4 address and port

	char astring[INET_ADDRSTRLEN];
	struct sockaddr_in *in4 = (struct sockaddr_in *)(addr);
	inet_ntop(AF_INET, &(in4->sin_addr), astring, INET_ADDRSTRLEN);
	printf(" IPv4 address %s", astring);
	printf(" and port %d\n", ntohs(in4->sin_port));

  } else if (addr->sa_family == AF_INET6) {
	// Print out the IPV6 address and port

	char astring[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)(addr);
	inet_ntop(AF_INET6, &(in6->sin6_addr), astring, INET6_ADDRSTRLEN);
	printf("IPv6 address %s", astring);
	printf(" and port %d\n", ntohs(in6->sin6_port));

  } else {
	printf(" ???? address and port ???? \n");
  }
}

void
PrintReverseDNS(struct sockaddr *addr, size_t addrlen) {
  char hostname[1024];  // ought to be big enough.
  if (getnameinfo(addr, addrlen, hostname, 1024, NULL, 0, 0) != 0) {
	sprintf(hostname, "[reverse DNS failed]");
  }
  printf("DNS name: %s \n", hostname);
}

void
PrintServerSide(int client_fd, int sock_family) {
  char hname[1024];
  hname[0] = '\0';

  printf("Server side interface is ");
  if (sock_family == AF_INET) {
	// The server is using an IPv4 address.
	struct sockaddr_in srvr;
	socklen_t srvrlen = sizeof(srvr);
	char addrbuf[INET_ADDRSTRLEN];
	getsockname(client_fd, (struct sockaddr *) &srvr, &srvrlen);
	inet_ntop(AF_INET, &srvr.sin_addr, addrbuf, INET_ADDRSTRLEN);
	printf("%s", addrbuf);
	// Get the server's dns name, or return it's IP address as
	// a substitute if the dns lookup fails.
	getnameinfo((const struct sockaddr *) &srvr,
            	srvrlen, hname, 1024, NULL, 0, 0);
	printf(" [%s]\n", hname);
  } else {
	// The server is using an IPv6 address.
	struct sockaddr_in6 srvr;
	socklen_t srvrlen = sizeof(srvr);
	char addrbuf[INET6_ADDRSTRLEN];
	getsockname(client_fd, (struct sockaddr *) &srvr, &srvrlen);
	inet_ntop(AF_INET6, &srvr.sin6_addr, addrbuf, INET6_ADDRSTRLEN);
	printf("%s", addrbuf);
	// Get the server's dns name, or return it's IP address as
	// a substitute if the dns lookup fails.
	getnameinfo((const struct sockaddr *) &srvr,
            	srvrlen, hname, 1024, NULL, 0, 0);
	printf(" [%s]\n", hname);
  }
}

int
Listen(char *portnum, int *sock_family) {

  // Populate the "hints" addrinfo structure for getaddrinfo().
  // ("man addrinfo")
  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;   	// IPv6 (also handles IPv4 clients)
  hints.ai_socktype = SOCK_STREAM;  // stream
  hints.ai_flags = AI_PASSIVE;  	// use wildcard "in6addr_any" address
  hints.ai_flags |= AI_V4MAPPED;	// use v4-mapped v6 if no v6 found
  hints.ai_protocol = IPPROTO_TCP;  // tcp protocol
  hints.ai_canonname = NULL;
  hints.ai_addr = NULL;
  hints.ai_next = NULL;

  // Use argv[1] as the string representation of our portnumber to
  // pass in to getaddrinfo().  getaddrinfo() returns a list of
  // address structures via the output parameter "result".
  struct addrinfo *result;
  int res = getaddrinfo(NULL, portnum, &hints, &result);

  // Did addrinfo() fail?
  if (res != 0) {
    printf( "getaddrinfo failed: %s", gai_strerror(res));
	return -1;
  }

  // Loop through the returned address structures until we are able
  // to create a socket and bind to one.  The address structures are
  // linked in a list through the "ai_next" field of result.
  int listen_fd = -1;
  struct addrinfo *rp;
  for (rp = result; rp != NULL; rp = rp->ai_next) {
	listen_fd = socket(rp->ai_family,
                   	rp->ai_socktype,
                   	rp->ai_protocol);
	if (listen_fd == -1) {
  	// Creating this socket failed.  So, loop to the next returned
  	// result and try again.
  	printf("socket() failed:%s \n ", strerror(errno));
  	listen_fd = -1;
  	continue;
	}

	// Configure the socket; we're setting a socket "option."  In
	// particular, we set "SO_REUSEADDR", which tells the TCP stack
	// so make the port we bind to available again as soon as we
	// exit, rather than waiting for a few tens of seconds to recycle it.
	int optval = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
           	&optval, sizeof(optval));

	// Try binding the socket to the address and port number returned
	// by getaddrinfo().
	if (bind(listen_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
  	// Bind worked!  Print out the information about what
  	// we bound to.
  	PrintOut(listen_fd, rp->ai_addr, rp->ai_addrlen);

  	// Return to the caller the address family.
  	*sock_family = rp->ai_family;
  	break;
	}

	// The bind failed.  Close the socket, then loop back around and
	// try the next address/port returned by getaddrinfo().
	close(listen_fd);
	listen_fd = -1;
  }

  // Free the structure returned by getaddrinfo().
  freeaddrinfo(result);

  // If we failed to bind, return failure.
  if (listen_fd == -1)
	return listen_fd;

  // Success. Tell the OS that we want this to be a listening socket.
  if (listen(listen_fd, SOMAXCONN) != 0) {
	printf("Failed to mark socket as listening:%s \n ", strerror(errno));
	close(listen_fd);
	return -1;
  }

  // Return to the client the listening file descriptor.
  return listen_fd;
}

void
HandleClient(int c_fd) {
  printf("\nNew client connection \n" );
 
  uint32_t fd;
  fd = open("./db", O_RDWR|O_CREAT, S_IRUSR|S_IWUSR); // correct?
  if (fd == -1) {
	perror("Failed to open database");
	exit(EXIT_FAILURE);
  }

  // Loop, waiting for dbclient messages
  while (1) {
	struct msg tsk;
 char* readBuf[260];
	ssize_t res = read(c_fd, readBuf, sizeof(readBuf));
 memcpy(&tsk, readBuf, sizeof(tsk));
	if (res == 0) {
  	printf("[The client disconnected.] \n");
  	break;
	} 

	if (res == -1) {
  	if ((errno == EAGAIN) || (errno == EINTR))
    	continue;

      printf(" Error on client socket:%s \n ", strerror(errno));
  	break;
	}
    
    
	struct msg rsp;
    
	uint8_t type = tsk.type;
	switch(type) {
  	case PUT:
    	rsp = (struct msg) put(fd, tsk.rd);
    	break;
  	case GET:
    	rsp = (struct msg) get(fd, tsk.rd);
  	default:
    	rsp.type = FAIL;
    	break;
	}
 char* writeBuf[260];
 memcpy(writeBuf, &rsp, sizeof(writeBuf));
	write(c_fd, writeBuf, sizeof(writeBuf));
  }
 
  close(fd);
  close(c_fd);
}

void* handle(void *arg) {
  int client_fd = *((int*) arg);
 
  HandleClient(client_fd);
  close(client_fd);
 
  return NULL;
}

// Store record r into database db and return
// a msg struct
struct msg
put(uint32_t fd, struct record r)
{    
    lseek(fd, 0, SEEK_CUR);
  write(fd, &r, sizeof(r));
 
  struct msg ret;
  ret.type = SUCCESS;
 
    return ret;
}

// read the database and return the most recent entry fo requested id
struct msg
get(uint32_t fd, struct record r)
{
  struct msg ret;
 
  // find out size of database
  uint32_t dbsize;
  dbsize = lseek(fd, 0, SEEK_END);
 
  // run through each record backwards from the last record of the database,
  // until a record with a matching id is found.
  uint32_t i = dbsize - 256;
  for (; i >= 0; i -= 256) {
	struct record rec;
	int rv = read(fd, &rec, sizeof(rec));
	if (rv == -1) {
  	ret.type = FAIL;
  	return ret;
	}
   	 
	if (r.id == rec.id) {
  	ret.type = SUCCESS;
  	strncpy(ret.rd.name, rec.name, MAX_NAME_LENGTH+1);
  	ret.rd.id = rec.id;
  	return ret;
	}
 	 
	lseek(fd, -256, SEEK_CUR);
  }
 
  lseek(fd, 0, SEEK_END);
    ret.type = FAIL;
  return ret;
}
