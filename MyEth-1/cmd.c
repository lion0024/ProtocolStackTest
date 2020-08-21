#include	<stdio.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<errno.h>
#include	<poll.h>
#include	<sys/ioctl.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/if_ether.h>
#include	<linux/if.h>
#include	<arpa/inet.h>
#include	<sys/wait.h>
#include	<pthread.h>
#include	"sock.h"
#include	"ether.h"
#include	"arp.h"
#include	"icmp.h"
#include	"param.h"
#include	"cmd.h"

extern int	DeviceSoc;

extern PARAM	Param;


/* ARPコマンド処理 */
int DoCmdArp(char **cmdline)
{
char	*ptr;

	/* strtok_rの戻り値は次のトークンへのポインタ */
	if((ptr=strtok_r(NULL," \r\n",cmdline))==NULL){
		printf("DoCmdArp:no arg\n");
		return(-1);
	}
	if(strcmp(ptr,"-a")==0){
		ArpShowTable();
		return(0);
	}
	else if(strcmp(ptr,"-d")==0){
		/* -dの後にIPアドレスが必要なため改行の削除を行う */
		if((ptr=strtok_r(NULL," \r\n",cmdline))==NULL){
			printf("DoCmdArp:-d no arg\n");
			return(-1);
		}
		struct in_addr	addr;
		inet_aton(ptr,&addr);
		if(ArpDelTable(&addr)){
			printf("deleted\n");
		}
		else{
			printf("not exists\n");
		}
		return(0);
	}
	else{
		printf("DoCmdArp:[%s] unknown\n",ptr);
		return(-1);
	}
}

/* pingコマンド処理 */
int DoCmdPing(char **cmdline)
{
char	*ptr;
struct in_addr	daddr;
int	size;

	if((ptr=strtok_r(NULL," \r\n",cmdline))==NULL){
		printf("DoCmdPing:no arg\n");
		return(-1);
	}
	inet_aton(ptr,&daddr);
	if((ptr=strtok_r(NULL,"\r\n",cmdline))==NULL){
		/* pingコマンドは第三引数でsizeを指定できる */
		size=DEFAULT_PING_SIZE;
	}
	else{
		size=atoi(ptr);
	}
	PingSend(DeviceSoc,&daddr,size);

	return(0);
}

/* ifconfigコマンド処理 */
int DoCmdIfconfig(char **cmdline)
{
char	buf1[80];

	/* ParamはMyEth.iniを読み込んで構造体に入れただけのもの
	 *動的に読み込んでいるわけではない */
	printf("device=%s\n",Param.device);
	printf("vmac=%s\n",my_ether_ntoa_r(Param.vmac,buf1));
	printf("vip=%s\n",inet_ntop(AF_INET,&Param.vip,buf1,sizeof(buf1)));
	printf("vmask=%s\n",inet_ntop(AF_INET,&Param.vmask,buf1,sizeof(buf1)));
	printf("gateway=%s\n",inet_ntop(AF_INET,&Param.gateway,buf1,sizeof(buf1)));
	printf("IpTTL=%d,MTU=%d\n",Param.IpTTL,Param.MTU);

	return(0);
}

/* 終了コマンド処理 */
int DoCmdEnd(char **cmdline)
{
	/* exit()ではなくSIGTERMなのはなぜか
	 * -> exit()は非同期シグナルセーフな関数ではないため */
	kill(getpid(),SIGTERM);

	return(0);
}

/* ARPスプーフィング処理コマンド */
/*int DoCmdAttack(char **cmdline)
{
	int count;
	for (count = 1; count <= 10; count = count + 1){
			ArpSend(DeviceSoc, ARPOP_REQUEST, 02:02:76:1b:0b:6e, 68:f7:28:da:fa:78, 02:02:76:1b:0b:6e, 68:f7:28:da:fa:78, 118.27.11.110, );
			sleep(3);
	}

}*/

/* コマンド処理 */
int DoCmd(char *cmd)
{
char	*ptr,*saveptr;

	if((ptr=strtok_r(cmd," \r\n",&saveptr))==NULL){
		printf("DoCmd:no cmd\n");
		printf("---------------------------------------\n");
		printf("arp -a : show arp table\n");
		printf("arp -d addr : del arp table\n");
		printf("ping addr [size] : send ping\n");
		printf("ifconfig : show interface configuration\n");
		printf("end : end program\n");
		printf("---------------------------------------\n");
		return(-1);
	}

	if(strcmp(ptr,"arp")==0){
		DoCmdArp(&saveptr);
		return(0);
	}
	else if(strcmp(ptr,"ping")==0){
		DoCmdPing(&saveptr);
		return(0);
	}
	else if(strcmp(ptr,"ifconfig")==0){
		DoCmdIfconfig(&saveptr);
		return(0);
	}
	else if(strcmp(ptr,"end")==0){
		DoCmdEnd(&saveptr);
		return(0);
	}
	else{
		printf("DoCmd:unknown cmd : %s\n",ptr);
		return(-1);
	}
}
