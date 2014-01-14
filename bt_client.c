#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>

#include <sys/time.h>
#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

log_struct log_ptr;

int main (int argc, char * argv[]){
  peer_t p1;
  bt_args_t bt_args;
  be_node * node; // top node in the bencoding
  int i;
  char seederIp[15];

  parse_args(&bt_args, argc, argv);


  if(bt_args.verbose == 1){
    //printf("Args:\n");
    printf("verbose: %d\n",bt_args.verbose);
    printf("save_file: %s\n",bt_args.save_file);
    printf("log_file: %s\n",bt_args.log_file);
    printf("torrent_file: %s\n", bt_args.torrent_file);
    
    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        print_peer(bt_args.peers[i]);
    }

    
  }

  //read and parse the torent file
  node = load_be_node(bt_args.torrent_file);

  if(bt_args.verbose){
    be_dump(node);
  }

  //main client loop
  printf("Starting Main Loop\n");
  bt_info_t bt_info;
  char t[10];
  parse_bt_info(&bt_info, node, &t,&bt_args);

   int isServer = 0;
    for(i=0;i<MAX_CONNECTIONS;i++){
      if(bt_args.peers[i] != NULL)
        isServer = 1;
    }

//Start of Seeder-Leecher Connection
    if(isServer == 0)
    { 
  
      makeSeederListen(&bt_args, &bt_info, &node);
    }
    else
    {   
      for(i=0;i<MAX_CONNECTIONS;i++)
      {
        if(bt_args.peers[i] != NULL)
        {
          int sockfd = socket(AF_INET, SOCK_STREAM, 0);
          printf("SOCKFD AT LEECHER: %d \n", sockfd);
          signed int tempConnect = 0;
          if((tempConnect = connect(sockfd, (struct sockaddr *) &bt_args.peers[i]->sockaddr, sizeof(bt_args.peers[i]->sockaddr)) < 0))
          {
            printf("\nError Number: %d\n", tempConnect);
            printf("\nerror while connecting\n");
            exit(1);
          }
          else
          {   
		if(bt_args.verbose == 1)         
	              printf("\nConnection established");
	        handleHandshaking(&bt_info, sockfd, bt_args.peers, bt_args.peers[i]->sockaddr, &bt_args, "");
          }
        }  
      }
    }
 //End of Seeder-Leecher Connection
}
