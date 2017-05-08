 #include<stdio.h>
 #include<stdlib.h>
 #include<string.h>
 #include<openssl/rsa.h>
 #include<openssl/pem.h>
 #include<openssl/err.h>
 #include<sys/socket.h>
 #include <sys/types.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/shm.h>

 #define OPENSSLKEY "test.key"
 #define PUBLICKEY "test_pub.key"
 #define BUFFER_SIZE 1024
 #define QUEUE   20
 #define MYPORT  66666

 char* my_decrypt(char *str,char *path_key);

 int main(void){
     char *source="i like dancing !";
     char *ptr_en,*ptr_de;
	 int server_sockfd = socket(AF_INET,SOCK_STREAM, 0);
	 struct sockaddr_in server_sockaddr;
	 server_sockaddr.sin_family = AF_INET;
	 server_sockaddr.sin_port = htons(MYPORT);
	 server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	 if(bind(server_sockfd,(struct sockaddr *)&server_sockaddr,sizeof(server_sockaddr))==-1)
	 {
		   perror("bind");
		   exit(1);
	 }

	 if(listen(server_sockfd,QUEUE) == -1)
	 {
		   perror("listen");
           exit(1);
	 }
	 char buffer[BUFFER_SIZE];
	 struct sockaddr_in client_addr;
	 socklen_t length = sizeof(client_addr);
	 int conn = accept(server_sockfd, (struct sockaddr*)&client_addr, &length);
	 if(conn<0)
	 {
		  perror("connect");
		  exit(1);
	 }
	 printf("connect\n");
	 while(1)
	 {
		
		recv(conn, buffer, sizeof(buffer),0);
		printf("receive:%s\n",buffer);
		ptr_de=my_decrypt(buffer,OPENSSLKEY);
		printf("after decrypt:%s\n",ptr_de);
		memset(buffer,0,sizeof(buffer));

	 }
  
     if(ptr_en!=NULL){
         free(ptr_en);
     }   
     if(ptr_de!=NULL){
         free(ptr_de);
     }
	 close(conn);
	 close(server_sockfd);
     return 0;
 }

  char *my_decrypt(char *str,char *path_key){
     char *p_de;
     RSA *p_rsa;
     FILE *file;
     int rsa_len;
     if((file=fopen(path_key,"r"))==NULL){
         perror("open key file error");
         return NULL;
     }
     if((p_rsa=PEM_read_RSAPrivateKey(file,NULL,NULL,NULL))==NULL){
         ERR_print_errors_fp(stdout);
         return NULL;
     }
     rsa_len=RSA_size(p_rsa);
     p_de=(unsigned char *)malloc(rsa_len+1);
     memset(p_de,0,rsa_len+1);
     if(RSA_private_decrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_de,p_rsa,RSA_NO_PADDING)<0){
        return NULL;
     }
     RSA_free(p_rsa);
     fclose(file);
     return p_de;
}
