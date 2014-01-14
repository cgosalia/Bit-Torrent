#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/time.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> //hashing pieces
#include <openssl/hmac.h>

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"


#define sha1_digest_length 20

log_struct log_ptr;


void calc_id(char * ip, unsigned short port, char *id){
  char data[256];
  int len;
  
  //format print
  len = snprintf(data,256,"%s%u",ip,port);  

  //id is just the SHA1 of the ip and port string
  SHA1((unsigned char *) data, len, (unsigned char *) id); 

  return;
}


/**
 * init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
 *
 *
 * initialize the peer_t structure peer with an id, ip address, and a
 * port. Further, it will set up the sockaddr such that a socket
 * connection can be more easily established.
 *
 * Return: 0 on success, negative values on failure. Will exit on bad
 * ip address.
 *   
 **/
int init_peer(peer_t *peer, char * id, char * ip, unsigned short port){
    
  struct hostent * hostinfo;
  //set the host id and port for referece
  memcpy(peer->id, id, ID_SIZE);
  peer->port = port;
    
  //get the host by name
  if((hostinfo = gethostbyname(ip)) ==  NULL){
    perror("gethostbyname failure, no such host?");
    herror("gethostbyname");
    exit(1);
  }
  
  //zero out the sock address
  bzero(&(peer->sockaddr), sizeof(peer->sockaddr));
      
  //set the family to AF_INET, i.e., Iternet Addressing
  peer->sockaddr.sin_family = AF_INET;
    
  //copy the address to the right place
  bcopy((char *) (hostinfo->h_addr), 
        (char *) &(peer->sockaddr.sin_addr.s_addr),
        hostinfo->h_length);
    
  //encode the port
  peer->sockaddr.sin_port = htons(port);
  
  return 0;

}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer){
  int i;

  if(peer){
    printf("peer: %s:%u ",
           inet_ntoa(peer->sockaddr.sin_addr),
           peer->port);
    printf("id: ");
    for(i=0;i<ID_SIZE;i++){
      printf("%02x",peer->id[i]);
    }
    printf("\n");
  }
}


int parse_bt_info(bt_info_t * bt_info, be_node * node, char * key,bt_args_t * bt_args)
{
  int i;  
    switch (node->type) 
    {
      case BE_STR:
	//check if the current key is name
        if(strcmp(key,"name")==0)
        {         
          strncpy(bt_info->name, node->val.s, be_str_len(node));
        }
	//check if the current key is pieces
        else if(strcmp(key,"pieces")==0)
        {
          
          bt_info->num_pieces = bt_info->length / bt_info->piece_length;
          if((bt_info->length % bt_info->piece_length) > 0 )
            bt_info->num_pieces += 1;
        	
	  //mallocing the double pointer 
          bt_info->piece_hashes = (char **)malloc(bt_info->num_pieces * sizeof(char *));
          char *tempPiece;
          
          int j;          

          for(j = 0; j < bt_info->num_pieces; j++)
          {
            tempPiece = (char *)malloc(20);
            tempPiece[20] = '\0';
            memset(tempPiece,'\0',20);
            bt_info->piece_hashes[j] = tempPiece; 
	    if(memcpy(bt_info->piece_hashes[j], node->val.s + (j*20), 20) != NULL)
            {  
		memcpy(bt_info->piece_hashes[j], node->val.s + (j*20), 20);                                        
            }
	    //free(tempPiece);            
           }	  
          }
	  //check if the key is announce
          else if(strcmp(key,"announce")==0)
          {         
           strncpy(bt_info->announce, node->val.s, be_str_len(node));
          }
          break;

      case BE_INT:
	//check if the key is piece length
        if(strcmp(key,"piece length")==0)
        {
          bt_info->piece_length = node->val.i;
        }
	//check if the key is length
        else if(strcmp(key,"length")==0)
        {        
          bt_info->length = node->val.i;
        }
        break;

      case BE_LIST:
        break;

      case BE_DICT:
         for (i = 0; node->val.d[i].val; ++i) 
          {
          	if(strcmp(node->val.d[i].key,"creation date") != 0)
            		parse_bt_info(bt_info, node->val.d[i].val, node->val.d[i].key,bt_args);
          }        
          break;
    }
  }

  void makeSeederListen(bt_args_t * bt_args, bt_info_t * bt_info, be_node * node)
  {
      int clntSock;

      in_port_t servPort = (unsigned short)8001;
      //Creating a socket for incoming connections
      int servSock; // Socket descriptor for server
      if ((servSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
      {
        //if(bt_args->verbose == 1)
	        printf("\nConnection to the socket failed");
      }
      else
      {
	if(bt_args->verbose == 1)
          printf("\nSocket connection established Successfully.");
      }
      // Constructing a local address structure
      struct sockaddr_in servAddr;                  // Local address
      memset(&servAddr, 0, sizeof(servAddr));       // Zero out structure
      servAddr.sin_family = AF_INET;                // IPv4 address family
      //handles -b functionality
      if(bt_args->connectip == 1)
      {
	printf("\nThe -b option lets leecher connect only with the specified ip");
      }
      else
      {
	printf("\n");
      }
      servAddr.sin_addr.s_addr = htonl(INADDR_ANY); // Any incoming interface
      servAddr.sin_port = htons(servPort);          // Local port

      // Bind to the local address
      if (bind(servSock, (struct sockaddr*) &servAddr, sizeof(servAddr)) < 0)
      {
        if(bt_args->verbose == 1)
        	printf("\nBinding failed");
      }
      else
      {
        if(bt_args->verbose == 1)
        	printf("\nBinding successful.");
      }


      // Mark the socket so it will listen for incoming connections
      if (listen(servSock, 5) < 0)
      {
        if(bt_args->verbose == 1)  
        	printf("listen() failed");
      }
      else
      {
        if(bt_args->verbose == 1)
          printf("\nlistening...\n");
      }
      for (;;) // Run forever
      {     
          struct sockaddr_in clntAddr; // Client address
          // Set length of client address structure (in-out parameter)
          socklen_t clntAddrLen = sizeof(clntAddr);

          // Wait for a client to connect
          clntSock = accept(servSock, (struct sockaddr *) &clntAddr, &clntAddrLen);
          if (clntSock < 0)
          {
            if(bt_args->verbose == 1)
            	printf("\nAccepting failed");
            exit(1);
          }
          else
          {
              if(bt_args->verbose == 1)
              	printf("\nAccepting a client...");
          }
          // clntSock is connected to a client!
          char clntName[INET_ADDRSTRLEN]; // String to contain client address
          if (inet_ntop(AF_INET, &clntAddr.sin_addr.s_addr, clntName,sizeof(clntName)) != NULL)
          {
            if(bt_args->verbose == 1)
            {
            	printf("Handling leecher %s/%d\n", clntName, ntohs(clntAddr.sin_port));
	        printf("\nPerforming handshaking...");
             }      
	          handleHandshaking(bt_info, clntSock, bt_args->peers, servAddr, bt_args,clntName);
    
          }
          else
          {
            if(bt_args->verbose == 1)
            	puts("Unable to get leecher address\n");
          }  
         
	}   	
  }

void handleHandshaking(bt_info_t * bt_info, int sockfd, peer_t * peers[MAX_CONNECTIONS], struct sockaddr_in servAddr, bt_args_t * bt_args,char clntName[])
{
    int done = 0;
    //extern unsigned char *serverIp;
    unsigned char handshake[68];
    memset(handshake,'\0',68);    
    //contains one byte representing 19, 19 bytes representing BitTorrent Protocol and 8 bytes of 0s that are reserved
    strcat(handshake,"\23BitTorrent Protocol00000000");
    handshake[68] = '\0';
    char hs_num_pieces[10]= "";
    sprintf(hs_num_pieces,"%d",bt_info->num_pieces);
    char str[(bt_info->num_pieces)*40];
    memset(str,'\0',(bt_info->num_pieces)*40);
    strcpy(str,"");
    int i;
    for(i=0;i<bt_info->num_pieces;i++)
    {
	strcat(str,bt_info->piece_hashes[i]);
    }
    char mdString[20]; 
    //calculates hash of str containing piece_hashes, it is later compared
    SHA1((unsigned char *) str, strlen(str), &mdString); 
    strcat(handshake, mdString); 
    int isServer = 0;       
    for(i=0;i<MAX_CONNECTIONS;i++)
    {
      if(peers[i] != NULL)
      {
        isServer = 1;
      }
    }
    
      unsigned short ownPort = servAddr.sin_port;
      //printf("Port: %u\n", ntohs(ownPort));
      char ownName[INET_ADDRSTRLEN]; // String to contain client address
      inet_ntop(AF_INET, &servAddr.sin_addr.s_addr, ownName,sizeof(ownName));
      //printf("Ip adrress: %s\n", ownName);
      
      char id[20];
      if (strcmp(ownName,"0.0.0.0") == 0)
      {
       char ownName1[] = "localhost";
       calc_id(&ownName1,ntohs(ownPort),&id);
      }
      else
      {
        calc_id(&ownName,ntohs(ownPort),&id);
      }
      //contains the hex value of the peer id, used in the logging_function
      unsigned char mdString1[EVP_MAX_MD_SIZE];	
      int j;    
      for(j = 0; j < 20; j++)
      		sprintf(&mdString1[j*2], "%02x", (unsigned int)id[j]);
    
      logging_function("HANDSHAKE INIT",clntName,ownPort,mdString1,0,0,0,0);
      handshake[48] = '\0';
      strcat(handshake, id);
      handshake[68] = '\0';

	
    if (send(sockfd, handshake, 68, 0) != 68)
    {
      if(bt_args->verbose == 1)
      {
      	printf("\nsend() sent a different number of bytes than expected");
      	printf("\nExiting...");
      }
      exit(0);
    }
    else
    {
      if(bt_args->verbose == 1)
      {
      	printf("\nSent Successfully.\n");
       }
      int bytesRcvd;
      char recvBuf[68];
      memset(recvBuf,'\0',68);
      if ((bytesRcvd = recv(sockfd, recvBuf, 68, 0)) <= 0)
      {
	//if(bt_args->verbose == 1)
	        printf("\nrecv() failed or connection closed prematurely\n");
      }
      recvBuf[68] = '\0';
      
      char ip[20];
      memset(ip,'\0',20);
      if(isServer != 0)
      {
        calc_id(bt_args->ip,ntohs(ownPort),&ip);        
        //printf("Hash of the server and port : %s\n", ip); 
      } 

      int j;    
      for(j =0 ; j< 48; j++)
      {
        if(handshake[j] != recvBuf[j])
		recvBuf[j] += 256;
      }      
      i = 0;      
      if(isServer != 0)
      {    
        for(j =48 ; j < 68; j++)
        {
          if(ip[i] != recvBuf[j])
		done = 1;
          i++;
        }     
      }
      if(strncmp((signed char *)recvBuf,(signed char *)handshake,48) == 0)
      {
          if(isServer != 0)
          {
            if(done == 1) 
            {
	      if(bt_args->verbose == 1)
              	printf("\nBad Hash!! Handshaking failed\n");
              exit(0);
            }
          }
	if(bt_args->verbose == 1)
	{
	        printf("\nHandshaking done\n");
	}
	logging_function("HANDSHAKE SUCCESS",clntName,ownPort,mdString1,0,0,0,0);        
        initiateExchange(sockfd, isServer, bt_info,clntName,ownPort,mdString1,bt_args);
      }
      else
      {
	//if(bt_args->verbose == 1)
	        printf("\nBad Hash!! Handshaking failed\n");
      }
    }
  }
	



void initiateExchange(int sockfd, int isServer, bt_info_t * bt_info, char clntName[],unsigned short ownPort,char mdString1[],bt_args_t * bt_args)
{
  int j = 0;
  if (isServer == 0)
  {
      bt_msg_t bitFieldMsg;
      bitFieldMsg.bt_type = 5;
      bitFieldMsg.payload.bitfiled.size  = bt_info->num_pieces;
      bitFieldMsg.payload.bitfiled.bitfield[bt_info->num_pieces] = '\0';

      int i;
      for(i = 0; i < bt_info->num_pieces; i++ )
      {
          bitFieldMsg.payload.bitfiled.bitfield[i] = '1';
      }
      bitFieldMsg.length = sizeof(bitFieldMsg.bt_type) + sizeof(bitFieldMsg.payload);
      
      int bytesSent;
      if((bytesSent = send(sockfd,(bt_msg_t *)&bitFieldMsg, sizeof(bitFieldMsg), 0)) != sizeof(bitFieldMsg))
      {
	if(bt_args->verbose == 1)
	       printf("BitField message could not be sent . Failed. Exiting...\n");
       logging_function("BITFIELD NOT SENT",clntName,ownPort,mdString1,0,0,0,0); 
      }
      else
      {
       //sends BitField Message 
       if(bt_args->verbose == 1)
       		printf("BitField sent.\n"); 
       logging_function("MSG SENT BITFIELD",clntName,ownPort,mdString1,0,0,0,0); 
      }
      //seeder accepts the Interested Message	
      if(acceptInterestedMessages(sockfd,bt_info) == 1)
      {
	if(bt_args->verbose == 1)
	        printf("Leecher is interested\n");
	logging_function("LEECHER INTERESTED",clntName,ownPort,mdString1,0,0,0,0); 
        initiateUnchoked(sockfd);
        
        int temp = 0;
        int totalChunks;
        totalChunks = bt_info->length / 8192;
        if(totalChunks % 8192 > 0)
        {
          totalChunks = totalChunks + 1;
        }
        

        int recvSize;
        do
        {
          bt_msg_t requestMsg;
          if(recvSize = (recv(sockfd, &requestMsg, sizeof(bt_msg_t),0)) > 0)  
          {
            if(requestMsg.bt_type == 8)
            {
	      if(bt_args->verbose == 1)
              	printf("Cancel message received\n");
	      logging_function("PROBLEM DURING REQUEST SEND",clntName,ownPort,mdString1,0,0,0,0); 
              break;
            }
            else if(requestMsg.bt_type == 6)
            {
	      if(bt_args->verbose == 1)
              		printf("Request message received\n");

            }

            bt_msg_t pieceMsg;
            pieceMsg.bt_type = 7;
            pieceMsg.payload.piece.index = requestMsg.payload.request.index;          
            pieceMsg.payload.piece.begin = requestMsg.payload.request.begin;          
            pieceMsg.length = (int) sizeof(pieceMsg.bt_type) + sizeof(pieceMsg.payload);
            FILE* fd = fopen(bt_info->name, "r+");             
            //FILE* fd = fopen("download.mp3", "rb+");             
            
            fseek(fd, temp * 8192, SEEK_SET);
            char mainBuffer[8192];
            mainBuffer[0]='\0';
            int qwe;
            if(temp == totalChunks - 1)
            {
              fread (mainBuffer, bt_info->length % 8192, 1, fd);
              mainBuffer[bt_info->length % 8192] = '\0';
              memset(pieceMsg.data, '\0', 8192);
              strncpy(pieceMsg.data,mainBuffer, bt_info->length % 8192);
		qwe = (bt_info->length % 8192) / 1024;
            }
            else
            {
              fread (mainBuffer, 8192, 1, fd);
              mainBuffer[8192] = '\0';
              memset(pieceMsg.data, '\0', 8192);
              strncpy(pieceMsg.data,mainBuffer, 8192);
		qwe = 8;
            }
            //int l;
           
            if(send(sockfd, &pieceMsg, sizeof(pieceMsg), 0) != sizeof(bt_msg_t))
            { 
		//if(bt_args->verbose == 1)     
              		printf("\nrequest message could not be sent . Failed. Exiting...\n");
            }
            else
            {
	      if(bt_args->verbose == 1)
              	printf("\nPiece Messge sent for %d packet offset %d\n", requestMsg.payload.request.index, requestMsg.payload.request.begin);
		
	      logging_function("MESSAGE PIECE",clntName,ownPort,mdString1,pieceMsg.payload.piece.index,pieceMsg.payload.piece.begin,qwe,1);
            }
          }
          temp++;
        }while(temp < totalChunks);
        
      }
      else
      {
	//if(bt_args->verbose == 1)
	        printf("Leecher is not interested. Disconnecting...\n");
	logging_function("LEECHER IS NOT INTERESTED",clntName,ownPort,mdString1,0,0,0,0);
        exit(0);
      }
  }
  else
  {  
    int bytesRcvd;
    bt_msg_t msg;
    if ((bytesRcvd = recv(sockfd,(bt_msg_t *)&msg, sizeof(bt_msg_t), 0)) <= 0)          
	//if(bt_args->verbose == 1)
        	printf("\nrecv() failed or connection closed prematurely\n");          
    msg.payload.bitfiled.bitfield[bt_info->num_pieces] = '\0';   

    initiateInterest(sockfd);
    //Leecher accepts the Unchoked Message
    if(acceptUnchokedMessages(sockfd, bt_info) == 1)
    {
      //if(bt_args->verbose == 1)
      		printf("The Leecher is now unchoked\n");  
      FILE* fd = fopen(bt_info->name, "r");
      FILE* fdi = fopen(bt_args->save_file, "a+");
      //FILE* fd = fopen("download.mp3", "rb");
      //FILE* fdi = fopen("download2.mp3", "a+");
   
      int iTrack;
      printf("Size: %d \n", bt_info->num_pieces);
      for(iTrack = 0; iTrack < bt_info->num_pieces; iTrack++)
      { 
        if(msg.payload.bitfiled.bitfield[iTrack]=='1')
        {          
   
          int t;
          if(iTrack < bt_info->num_pieces - 1)
          {
            t = bt_info->piece_length / 8192;
            if(bt_info->piece_length % 8192 > 0)
            {
              t = t + 1;
            }
          }
          else if(iTrack == bt_info->num_pieces - 1)
          {
            int lastPiece;
            lastPiece = bt_info->length % bt_info->piece_length;
            t = lastPiece / 8192;
            if(lastPiece % 8192 > 0)
            {
              t = t + 1;
            }
          }
          char *superBuffer;          
          int k;
          for(k = 0; k < t; k++)
          {
            bt_msg_t requestMsg;
            requestMsg.bt_type = 6;          
            requestMsg.payload.request.index = iTrack;
            requestMsg.payload.request.begin = k;
            requestMsg.payload.request.length = 8192;
            requestMsg.length = sizeof(requestMsg.bt_type) + sizeof(requestMsg.payload);
	    if(bt_args->verbose == 1)
            	printf("Sending request message for packet: %d and offset %d: \n", iTrack, k);
            if(send(sockfd, &requestMsg, sizeof(bt_msg_t), 0) != sizeof(bt_msg_t))
            {
	      //if(bt_args->verbose == 1)      
              printf("request message could not be sent . Failed. Exiting...\n");
              bt_msg_t cancelMsg;
              cancelMsg.bt_type = 8;                      
              cancelMsg.length = sizeof(cancelMsg.bt_type) + sizeof(cancelMsg.payload);          
              if(send(sockfd,&cancelMsg, sizeof(cancelMsg), 0) != sizeof(cancelMsg))
              { 
		//if(bt_args->verbose == 1)     
	                printf("request message could not be sent . Failed. Exiting...\n");
              }
              else
              {
		//if(bt_args->verbose == 1)
                	printf("Cancel message sent\n");                        
              }    
              exit(1);
            }
            else
            {
	      if(bt_args->verbose == 1)
              		printf("Request message sent for %d packet\n", j);              
              bt_msg_t pieceMsg;
              
              if((recv(sockfd, &pieceMsg, sizeof(bt_msg_t),0)) != sizeof(bt_msg_t))  
              {
		//if(bt_args->verbose == 1)
	                  printf("Problem occured while receving the piece message.\n");
              }
              else
              {
                if(pieceMsg.bt_type == 7)
                {
                //printf("Piece Message received.\n");
                //printf("Index: %d\n", pieceMsg.payload.piece.index);
                //printf("Begin: %d\n", pieceMsg.payload.piece.begin);
                //printf("Data: %s\n", pieceMsg.data);                                
                if(k == t-1)
                {
                  pieceMsg.data[bt_info->length % 8192] = '\0';
                  fwrite(pieceMsg.data, bt_info->length % 8192, 1, fdi);
                }
                else
                {
                  pieceMsg.data[8192] = '\0';
                  fwrite(pieceMsg.data, 8192, 1, fdi);

                }
                fflush(fdi);
                }
              }
            }
          }
	  print_status(bt_info, 1, iTrack);
	  //Not tested for SHA1
          /*superBuffer[bt_info->piece_length] = '\0';
          strcat(superBuffer, pieceMsg.data);
          short len = strlen(superBuffer);
          char * id;
          SHA1((unsigned char *) superBuffer, len, (unsigned char *) id); 
          printf("Hash1: %s\n", id);
          if(strncmp(id,bt_info->piece_hashes[iTrack],20) == 0)
          { 
            printf("Piece %d is received properly.", iTrack);
          }
          else
          {
            printf("Piece %d is not received properly\n", iTrack);
          }*/
        }        
      }
    }
  }
}
void initiateInterest(int sockfd)
{
   bt_msg_t interestMsg; 
   interestMsg.bt_type = 2;
   interestMsg.length = 1;
   if(send(sockfd,&interestMsg, sizeof(interestMsg), 0) != sizeof(interestMsg))
   {      
     printf("interest message could not be sent . Failed. Exiting...\n");
   }
}
void initiateUnchoked(int sockfd)
{
   bt_msg_t interestMsg; 
   interestMsg.bt_type = 1;
   interestMsg.length = 1;
   if(send(sockfd,&interestMsg, sizeof(interestMsg), 0) != sizeof(interestMsg))
   {      
     printf("unchoked message could not be sent . Failed. Exiting...\n");
   }
}

int acceptInterestedMessages(int sockfd, bt_info_t * bt_info)
{
    int bytesRcvd;
    bt_msg_t msg;
    if ((bytesRcvd = recv(sockfd,(bt_msg_t *)&msg, sizeof(bt_msg_t), 0)) <= 0)          
    {
      printf("\nrecv() failed or connection closed prematurely\n");
      return 0;
    }
    if(msg.bt_type == 2)
      return 1;
    return 0;
}


int acceptUnchokedMessages(int sockfd, bt_info_t * bt_info)
{
    int bytesRcvd;
    bt_msg_t msg;
    if ((bytesRcvd = recv(sockfd,(bt_msg_t *)&msg, sizeof(bt_msg_t), 0)) <= 0)          
    {
      printf("\nrecv() failed or connection closed prematurely\n");
      return 0;
    }
    if(msg.bt_type == 1)
      return 1;
    return 0;
}

void print_status(bt_info_t * bt_info, int peersCount, int index)
{
  float percentage;
  percentage = (index * 256);
  //percentage = percentage + (begin * 8);
  percentage = percentage / (bt_info->length / 1024);
  percentage = percentage * 100;
  int kb;
  if(index == bt_info->num_pieces -1)
  {
    kb = bt_info->length / 1024;
    percentage = 100.0;
  }
  else
    kb = (index * 256);
  printf("File: %s Progess: %0.2f %% Peers:%d Downloaded: %d KB\n", bt_info->name, percentage, peersCount, kb);
}

//function for logging information
void logging_function(char* message,char clntName[],unsigned char mdString1[],unsigned short ownPort,int index, int begin, int length, int n) {
	fflush(log_ptr.logging_file);
	float exact_time;
	gettimeofday(&(log_ptr.current_time),NULL);
	exact_time = (log_ptr.current_time.tv_usec - log_ptr.starting_time.tv_usec);
	//printf("[%.02f] %s, peer: %s, port: %hu\n",exact_time,message,clntName,ownPort);
	if(n==1)
		fprintf(log_ptr.logging_file,"[%.02f] %s, peer: %s, port: %hu,id: %x, index: %d,begin: %d,length: %d\n",exact_time,message,clntName,ownPort,mdString1,index,begin,length);
	else if(n==0)
		fprintf(log_ptr.logging_file,"[%.02f] %s, peer: %s, port: %hu,peer id:%x\n",exact_time,message,clntName,ownPort,mdString1);
	
	fflush(log_ptr.logging_file);
}

