 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <openssl/rsa.h>
 #include <openssl/pem.h>
 #include <openssl/err.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <sys/shm.h>

 #define OPENSSLKEY "test.key"
 #define PUBLICKEY "test_pub.key"
 #define BUFFER_SIZE 1024
 #define MYPORT  66666

 char* my_encrypt(char *str,char *path_key);//解密
 int main(void)
 {
	 char *ptr_en,*ptr_de;
     int sock_cli = socket(AF_INET,SOCK_STREAM, 0);
	 struct sockaddr_in servaddr;
	 memset(&servaddr, 0, sizeof(servaddr));
	 servaddr.sin_family = AF_INET;
	 servaddr.sin_port = htons(MYPORT);
	 servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	 if (connect(sock_cli, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
	 {
		 perror("connect");
		 exit(1);
	 }
	 char sendbuf[BUFFER_SIZE];
	 char recvbuf[BUFFER_SIZE];
	 while (fgets(sendbuf, sizeof(sendbuf), stdin) != NULL)
	 {
		 ptr_en=my_encrypt(sendbuf,PUBLICKEY);
		 printf("after encrypt:%s\n",ptr_en);
		 send(sock_cli, ptr_en, strlen(ptr_en),0);
		// send(sock_cli, sendbuf, strlen(sendbuf),0);
		 memset(sendbuf,0,sizeof(sendbuf));
	 }
	 close(sock_cli);
 }


char *my_encrypt(char *str,char *path_key){
     char *p_en;
     RSA *p_rsa;
     FILE *file;
     int flen,rsa_len;
     if((file=fopen(path_key,"r"))==NULL){
         perror("open key file error");
         return NULL;    
     }   
     if((p_rsa=PEM_read_RSA_PUBKEY(file,NULL,NULL,NULL))==NULL){
     //if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
         ERR_print_errors_fp(stdout);
         return NULL;
     }   
     flen=strlen(str);
     rsa_len=RSA_size(p_rsa);
     p_en=(unsigned char *)malloc(rsa_len+1);
     memset(p_en,0,rsa_len+1);
     if(RSA_public_encrypt(rsa_len,(unsigned char *)str,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING)<0){
         return NULL;
     }
     RSA_free(p_rsa);
     fclose(file);
     return p_en;
 }