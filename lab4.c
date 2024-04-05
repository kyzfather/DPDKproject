#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include <rte_kni.h>
#include <arpa/inet.h> 
#include <netinet/ip.h>  
#include <netinet/in.h> 
#include <pcap/pcap.h>  
#include <rte_lcore.h> 
#include <rte_cycles.h>  
#include <inttypes.h>  
#include <unistd.h>

#include "dns.h"

/* 
   实现DNS服务器的多线程处理，并使用RSS流分类技术，将网卡收到的数据包均匀分到不同的队列中，每个核处理自己指定的队列
   通过参数来指定每个核处理哪个网卡的哪个队列 (port,queue,lcore)
   代码实现：参考l2fwd.c和l3fwd.c 以及实验3的dpdk_udp.c
   enp0s8: ipv4:222.195.90.45  mac:08:00:27:3a:90:84
   enp0s9: ipv4:211.86.152.134 mac:08:00:27:2a:b6:2e
   enp0s10 ipv4:222.195.90.136 mac:08:00:27:37:da:ac
   sudo ./build/dpdk_udp -l 0,1,2,3 -- -p 0x7 --config="(0,0,0),(1,0,1),(2,0,2)"
   dig @222.195.90.45 foo.bar.com A
   dig @211.86.152.134 foo.bar.com A
   dig @222.195.90.136 foo.bar.com A
*/

#define MBUF_NUMBER 8196
#define MEMPOOL_CACHE_SIZE 256 
#define MAX_RX_QUEUE_PER_LCORE 16

#define MAX_PKT_BURST 32

#define RTE_ETHER_ADDR_LEN 6
#define RTE_ETHER_TYPE_IPV4 0x0800
#define RTE_ETHER_MAX_LEN 1500

#define MAX_LCORE_PARAMS  1024

#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define DNS_UDP_PORT	53

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static int promiscuous_on;
static volatile bool force_quit;
static uint16_t nb_ports;

/* 
  ????有个问题，全局变量，在rte_eal_mp_remote_launch创建多个线程的时候，这些变量会拷贝到每个线程吗？
  还是说这些线程共享这些变量
*/
// static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
// static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

// static uint32_t gSrcIp; 
// static uint32_t gDstIp;

// static uint16_t gSrcPort;
// static uint16_t gDstPort;

struct rte_mempool* mbuf_pool;

//用于解析参数的(port, queue, lcore)
struct lcore_params {
    uint16_t port_id;
    uint8_t queue_id;
    uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_array_default[] = {
	{0, 0, 2},
	{0, 1, 2},
	{0, 2, 2},
	{1, 0, 2},
	{1, 1, 2},
	{1, 2, 2},
	{2, 0, 2},
	{3, 0, 3},
	{3, 1, 3},
};

static struct lcore_params* lcore_params = lcore_params_array_default;
static uint16_t nb_lcore_params = sizeof(lcore_params_array_default) / sizeof(lcore_params_array_default[0]);
 
//l3fwd中一些用于解析的数据结构，具体怎么解析的没有细看。有些功能用不上
static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"L"   /* enable long prefix match */
	"E"   /* enable exact match */
	;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_NO_NUMA "no-numa"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_ENABLE_JUMBO "enable-jumbo"
#define CMD_LINE_OPT_HASH_ENTRY_NUM "hash-entry-num"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"
enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_ETH_DEST_NUM,
	CMD_LINE_OPT_NO_NUMA_NUM,
	CMD_LINE_OPT_IPV6_NUM,
	CMD_LINE_OPT_ENABLE_JUMBO_NUM,
	CMD_LINE_OPT_HASH_ENTRY_NUM_NUM,
	CMD_LINE_OPT_PARSE_PTYPE_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
	{CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
	{CMD_LINE_OPT_IPV6, 0, 0, CMD_LINE_OPT_IPV6_NUM},
	{CMD_LINE_OPT_ENABLE_JUMBO, 0, 0, CMD_LINE_OPT_ENABLE_JUMBO_NUM},
	{CMD_LINE_OPT_HASH_ENTRY_NUM, 1, 0, CMD_LINE_OPT_HASH_ENTRY_NUM_NUM},
	{CMD_LINE_OPT_PARSE_PTYPE, 0, 0, CMD_LINE_OPT_PARSE_PTYPE_NUM},
	{NULL, 0, 0, 0}
};


struct lcore_rx_queue {
    uint16_t port_id;
    uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
    uint16_t n_rx_queue;
    struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
    uint16_t n_tx_port;
    uint16_t tx_port_id[RTE_MAX_ETHPORTS];
    uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
    
} __rte_cache_aligned;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

uint32_t enabled_port_mask;

static int init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			printf("error: too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
			return -1;
		} else {
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
				lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
				lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
		}
	}
	return 0;
}

static uint8_t get_port_n_rx_queues(const uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue+1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
						" in sequence and must start with 0\n",
						lcore_params[i].port_id);
		}
	}
	return (uint8_t)(++queue);
}

//解析参数中的端口掩码 识别开启哪些端口
static int parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* display usage */
static void print_usage(const char *prgname)
{
	fprintf(stderr, "%s [EAL options] --"
		" -p PORTMASK"
		" [-P]"
		" [-E]"
		" [-L]"
		" --config (port,queue,lcore)[,(port,queue,lcore)]"
		" [--eth-dest=X,MM:MM:MM:MM:MM:MM]"
		" [--enable-jumbo [--max-pkt-len PKTLEN]]"
		" [--no-numa]"
		" [--hash-entry-num]"
		" [--ipv6]"
		" [--parse-ptype]\n\n"

		"  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  -E : Enable exact match\n"
		"  -L : Enable longest prefix match (default)\n"
		"  --config (port,queue,lcore): Rx queue configuration\n"
		"  --eth-dest=X,MM:MM:MM:MM:MM:MM: Ethernet destination for port X\n"
		"  --enable-jumbo: Enable jumbo frames\n"
		"  --max-pkt-len: Under the premise of enabling jumbo,\n"
		"                 maximum packet length in decimal (64-9600)\n"
		"  --no-numa: Disable numa awareness\n"
		"  --hash-entry-num: Specify the hash entry number in hexadecimal to be setup\n"
		"  --ipv6: Set if running ipv6 packets\n"
		"  --parse-ptype: Set to use software to analyze packet type\n\n",
		prgname);
}


//解析参数中的(port, queue, lcore)
static int parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_lcore_params = 0;

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++){
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			printf("exceeded max number of lcore params: %hu\n",
				nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id =
			(uint8_t)int_fld[FLD_PORT];
		lcore_params_array[nb_lcore_params].queue_id =
			(uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id =
			(uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	lcore_params = lcore_params_array;
	return 0;
}

/* Parse the argument given in the command line of the application */
static int parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				fprintf(stderr, "Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case 'P':
			promiscuous_on = 1;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = parse_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				print_usage(prgname);
				return -1;
			}
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}


static struct rte_mbuf *alloc_udp_pkt(struct rte_mempool *pool, uint8_t *data, uint16_t length, uint8_t* gSrcMac, uint8_t* gDstMac,
	uint32_t gSrcIp, uint32_t gDstIp, uint16_t gSrcPort, uint16_t gDstPort) {

// 32, 2048 + hdrsize
	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pool);  //
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc error\n");
	}

	mbuf->pkt_len = length + sizeof(struct ipv4_hdr) + sizeof(struct ether_hdr);
	mbuf->data_len = length + sizeof(struct ipv4_hdr) + sizeof(struct ether_hdr);

	uint8_t *msg = rte_pktmbuf_mtod(mbuf, uint8_t*);
	// ether 
	struct ether_hdr *eth = (struct ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	// 6 + 
	/* 6 bytes    6 bytes    2 bytes
	 +----------+----------+------+
	 | src mac  | dst mac  | type |
	 +----------+----------+------+
	 */

	// iphdr
	struct ipv4_hdr *ip = (struct ipv4_hdr *)(msg + sizeof(struct ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(length + sizeof(struct ipv4_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// udphdr
	struct udp_hdr *udp = (struct udp_hdr *)(msg + sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	//uint16_t udplen = length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(length);

	rte_memcpy((uint8_t*)(udp+1), data, length-sizeof(struct udp_hdr));

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	
	return mbuf;
}


static int process_function(__attribute__((unused)) void *dummy) {
	uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
    uint8_t gDstMac[RTE_ETHER_ADDR_LEN];
	uint32_t gSrcIp; 
	uint32_t gDstIp;
	uint16_t gSrcPort;
	uint16_t gDstPort;

    unsigned lcore_id;
    unsigned nb_rx;
    struct lcore_conf* qconf;
    struct rte_mbuf* mbufs[MAX_PKT_BURST];

    lcore_id = rte_lcore_id();
    qconf = &lcore_conf[lcore_id];

	struct Message msg;
  	memset(&msg, 0, sizeof(struct Message));

	if (qconf->n_rx_queue == 0) {
		printf("lcore %u has nothing to do\n", lcore_id);
		return;
	} else 
		printf("lcore %d is working\n", lcore_id);

    while (1) {
        //从相应的网卡队列中读取数据
        for (int i = 0; i < qconf->n_rx_queue; i++) {
            struct lcore_rx_queue pairs = qconf->rx_queue_list[i];
            uint16_t temp_port_id = pairs.port_id;
            uint8_t temp_queue_id = pairs.queue_id;
            //接下来就是实验3 dpdk_udp里的代码逻辑
            nb_rx = rte_eth_rx_burst(temp_port_id, temp_queue_id, mbufs, MAX_PKT_BURST);
            if (nb_rx > MAX_PKT_BURST)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_burst Error\n");

			/*if (nb_rx != 0)
				printf("lcore %d receive %d msgs\n", lcore_id, nb_rx);		*/	
            for (int j = 0; j < nb_rx; j++) {
                struct ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[j], struct ether_hdr *);

                if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) 
                    continue;

                struct ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[j], struct ipv4_hdr *, sizeof(struct ether_hdr));
                if (iphdr->next_proto_id == IPPROTO_UDP) {
	
                    struct udp_hdr* udphdr = (struct udp_hdr*)(iphdr + 1);
                    if (ntohs(udphdr->dst_port) == DNS_UDP_PORT) {

						printf("lcore %d receive a DNS quest\n", lcore_id);

                        rte_memcpy(gSrcMac, ehdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                        rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
                        
                        rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                        rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));
        
                        rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                        rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

                        uint16_t length = ntohs(udphdr->dgram_len);
                        uint16_t nbytes = length - sizeof(struct udp_hdr);
                        
                        
                        uint8_t *data = (uint8_t*)(udphdr + 1);                        

                        free_questions(msg.questions);
                        free_resource_records(msg.answers);
                        free_resource_records(msg.authorities);
                        free_resource_records(msg.additionals);
                        memset(&msg, 0, sizeof(struct Message));

                        if (decode_msg(&msg, data, nbytes) != 0) {
						    rte_pktmbuf_free(mbufs[j]); // 
				    	    continue;
				        }

                        resolve_query(&msg);

                        uint8_t *p = data;
                        if (encode_msg(&msg, &p) != 0) {
                            rte_pktmbuf_free(mbufs[j]);
                            continue;
                        }

                        uint16_t len = p - data;

                        struct rte_mbuf *mbuf = alloc_udp_pkt(mbuf_pool, data, len+sizeof(struct udp_hdr), gSrcMac, gDstMac,
												gSrcIp, gDstIp, gSrcPort, gDstPort);

                        //每个网卡有lcore个发送队列，所以每个lcore可以往任意的网卡发送数据。
                        // srand((unsigned)time(NULL));
                        // int temp_port  = rand() % nb_ports;
						int temp_port = lcore_id % 3;
						printf("lcore %d send to port %d\n", lcore_id, temp_port);
					    //rte_eth_tx_burst(temp_port, lcore_id - 1, &mbuf, 1); 服务器使用这行代码
						rte_eth_tx_burst(lcore_id % 3, 0, &mbuf, 1); //虚拟机使用这行代码。因为虚拟机网卡只有一个接收队列。

                    } //端口对应DNS服务的端口

                } //如果满足udp包

            } //每个接收到的数据包

        } //从与该核对应的每一个网卡接受队列

    } //无限循环，持续接收DNS请求
    return 0;
}

int main(int argc, char** argv) {
    int ret;
    uint16_t nb_ports;
    uint16_t queueid, portid;
    unsigned lcore_id;
    uint32_t n_tx_queue, nb_lcores;
    uint8_t nb_rx_queue;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf* txconf;
    struct lcore_conf* qconf;

    //初始化DPDK运行环境
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invaild EAL arguments\n");
    argc -= ret;
    argv += ret;
    nb_lcores = rte_lcore_count();
    nb_ports = rte_eth_dev_count_avail();
	printf("ports count = %d \n\n", nb_ports);
    if (nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

    //解析程序的参数
    ret = parse_args(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid parameters\n");

    ret = init_lcore_rx_queues();
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Init_lcore_rx_queues failed\n");


    //分配申请mbuf_pool
    mbuf_pool = rte_pktmbuf_pool_create("mbufpool", MBUF_NUMBER, MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id()); //???这个cache有什么用
    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    //网卡设置 以及tx发送队列设置
    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_conf local_port_conf = port_conf;

        nb_rx_queue = get_port_n_rx_queues(portid);
        //n_tx_queue = nb_lcores; 虚拟机不支持网卡多队列，一个网卡只能有一个发送队列和一个接收队列。服务器使用这行代码
		n_tx_queue = 1; //虚拟机使用这行代码

        rte_eth_dev_info_get(portid, &dev_info);
        if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;

        //从l3fwd拷贝过来的  rss的设置
		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf.rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function based on hardware support,"
				"requested:%#"PRIx64" configured:%#"PRIx64"\n",
				portid,
				port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

        ret = rte_eth_dev_configure(portid, nb_rx_queue, (uint16_t)n_tx_queue, &local_port_conf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", ret, portid);

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd); //？？？什么意思
    	if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot adjust number of descriptors: err=%d, port=%d\n", ret, portid);
        
        
        //设置port以及lcore的tx队列
		/* 服务器使用该部分代码
        queueid = 0;
        for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
            if (rte_lcore_is_enabled(lcore_id) == 0)
                continue;

            txconf = &dev_info.default_txconf;
            txconf->offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, rte_eth_dev_socket_id(portid), txconf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
            
            qconf = &lcore_conf[lcore_id];
            qconf->tx_queue_id[portid] = queueid;
            queueid++;

            qconf->tx_port_id[qconf->n_tx_port] = portid;
            qconf->n_tx_port++;
        }
		*/

		//虚拟机使用这部分代码
        txconf = &dev_info.default_txconf;
        txconf->offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, rte_eth_dev_socket_id(portid), txconf);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);

		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			qconf = &lcore_conf[lcore_id];
			qconf->tx_queue_id[portid] = 0;

			qconf->tx_port_id[qconf->n_tx_port] = portid;
			qconf->n_tx_port++;
		}
		//虚拟机使用这部分代码


        printf("\n");
    }

    //rx接收队列设置
	struct rte_eth_conf local_port_conf = port_conf;
    for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
        if (rte_lcore_is_enabled(lcore_id) == 0)
            continue;

        qconf = &lcore_conf[lcore_id];
        printf("\nInitializing rx queues on lcore %u ... ", lcore_id);
        for (int queue = 0; queue < qconf->n_rx_queue; ++queue) {
            struct rte_eth_dev* dev;
            struct rte_eth_conf* conf;
            struct rte_eth_rxconf rxq_conf;

            portid = qconf->rx_queue_list[queue].port_id;
            queueid = qconf->rx_queue_list[queue].queue_id;
            dev = &rte_eth_devices[portid];  //这个好像没定义
            conf = &dev->data->dev_conf; //?????

            rte_eth_dev_info_get(portid, &dev_info);
            rxq_conf = dev_info.default_rxconf;
			//rxq_conf.offloads = local_port_conf.rxmode.offloads;
            rxq_conf.offloads = conf->rxmode.offloads; 
            ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, mbuf_pool);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, portid);
        }
    }

    printf("\nhhhhh\n");

    //开启网卡
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0) 
            continue;

        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", ret, portid);

        if (promiscuous_on)
            rte_eth_promiscuous_enable(portid);
    }

    printf("\n");

    //启动每个核
    ret = 0;
    rte_eal_mp_remote_launch(process_function, NULL, CALL_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    //关闭网卡
    RTE_ETH_FOREACH_DEV(portid) {
        if ((enabled_port_mask & (1 << portid)) == 0)
            continue;
        printf("Closing port %d...", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
        printf("Done\n");
    }
    printf("Bye...\n");

    return ret;
}