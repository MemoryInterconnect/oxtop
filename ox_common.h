#ifndef __OMEM_H__
#define __OMEM_H__

#define NUM_CONNECTION	4	// Maximum number of connection
#define MEM_SIZE		(8ULL * 1024 * 1024 * 1024)	// 8GB
#define RECV_BUFFER_SIZE	2048


#define OX_START_ADDR	0x0
#define OX_ETHERTYPE	0xAAAA

#define NORMAL			0
#define ACK_ONLY		1
#define OPEN_CONN		2
#define CLOSE_CONN		3

#define NACK			0
#define ACK				1

#define CHANNEL_A		1
#define CHANNEL_B		2
#define CHANNEL_C		3
#define CHANNEL_D		4
#define CHANNEL_E		5

// Channel A
#define A_PUTFULLDATA_OPCODE	0
#define A_PUTPARTIALDATA_OPCODE	1
#define A_ARITHMETICDATA_OPCODE	2
#define A_LOGICALDATA_OPCODE	3
#define A_GET_OPCODE		4
#define A_INTENT_OPCODE		5
#define A_ACQUIREBLOCK_OPCODE	6
#define A_ACQUIREPERM_OPCODE	7

// Channel B
#define B_PUTFULLDATA_OPCODE	0
#define B_PUTPARTIALDATA_OPCODE	1
#define B_ARITHMETICDATA_OPCODE	2
#define B_LOGICALDATA_OPCODE	3
#define B_GET_OPCODE		4
#define B_INTENT_OPCODE		5
#define B_PROBEBLOCK_OPCODE	6
#define B_PROBEPERM_OPCODE	7

// Channel C
#define C_ACCESSACK_OPCODE	0
#define C_ACCESSACKDATA_OPCODE	1
#define C_HINTACK_OPCODE	2
#define C_PROBEACK_OPCODE	4
#define C_PROBEACKDATA_OPCODE	5
#define C_RELEASE_OPCODE	6
#define C_RELEASEDATA_OPCODE	7

// Channel D
#define D_ACCESSACK_OPCODE	0
#define D_ACCESSACKDATA_OPCODE	1
#define D_HINTACK_OPCODE	2
#define D_GRANT_OPCODE		4
#define D_GRANTDATA_OPCODE	5
#define D_RELEASEACK_OPCODE	6

// Channel E
#define E_GRANTACK		0	// Not required opcode

struct ox11_header {
    uint64_t dst_mac_addr:48;
    uint64_t src_mac_addr:48;
    unsigned short eth_type;
    uint64_t be64_tloe_header;
    uint64_t be64_tl_msg;
    uint64_t be64_tl_data_start;
} __attribute__((__packed__));

struct ox_connection {
    uint64_t src_mac_addr:48;
    unsigned int seq_num:22;
    unsigned int seq_num_expected:22;
    unsigned char credit:5;
};

struct eth_header {
    uint64_t dst_mac_addr:48;
    uint64_t src_mac_addr:48;
    unsigned short eth_type;
} __attribute__((__packed__));

/* TLoE Header in Host Endian (LE) */
struct tloe_header {
    unsigned char credit:5;
    unsigned char chan:3;
    unsigned char reserve3:1;
    unsigned char ack:1;
    unsigned int seq_num_ack:22;
    unsigned int seq_num:22;
    unsigned char reserve2:2;
    unsigned char reserve1:1;
    unsigned char msg_type:4;
    unsigned char vc:3;
} __attribute__((packed, aligned(8)));

struct tl_msg_header_chan_AD {
    unsigned int source:26;
    unsigned int reserve1:12;
    unsigned int err:2;
    unsigned int domain:8;
    unsigned int size:4;
    unsigned int param:4;
    unsigned int reserve2:1;
    unsigned int opcode:3;
    unsigned int chan:3;
    unsigned int reserve3:1;
} __attribute__((packed, aligned(8)));

struct ox_packet_struct {
    struct eth_header eth_hdr;
    struct tloe_header tloe_hdr;
    uint64_t tl_msg_mask;
    uint32_t flit_cnt;
    uint64_t *flits;
};

#if 0
#define PRINT_LINE(fmt, args...) printf("%s %d - " fmt, __FUNCTION__, __LINE__, ##args)
#else
#define PRINT_LINE(fmt, args...)
#endif

// functions
/*int get_connection(struct ox_packet_struct *);
int delete_connection(int) ;
int create_new_connection(struct ox_packet_struct *);
int is_ox_header(struct ox_packet_struct *); 
void print_hex(char *, int);
void print_ox_header(struct ox_packet_struct *);
void print_flits(struct ox_packet_struct *); 
void print_tl_msg_header(struct tl_msg_header_chan_AD *);
void print_payload(char *, int);
void make_response_packet_template(int, struct ox_packet_struct *, struct ox_packet_struct *);
void build_ethernet_header(struct ox_packet_struct *, struct ox_packet_struct *);
void build_tLoE_frame_header(int, struct ox_packet_struct *, struct ox_packet_struct *); 
void build_tl_msg_header(const struct tl_msg_header_chan_AD, struct ox_packet_struct *, int, int);
void build_tl_message_b(struct tl_msg_header_chan_AD, struct ox_packet_struct *, uint64_t *, int, int);
void build_tloe_frame_mask(uint64_t *);
//void write_data(struct ox_packet_struct *, int);
//void read_data(struct ox_packet_struct *, uint64_t *, int);
int send_ack(int, int, struct ox_packet_struct *);
int send_close_connection(int, int, struct ox_packet_struct *); 
int handle_normal_packet(int, int, struct ox_packet_struct *);
int get_ox_msg_type(struct ox_packet_struct *); 
int get_ox_channel(char *); */

void build_ethernet_header(struct ox_packet_struct *,
			   struct ox_packet_struct *);
void build_tLoE_frame_header(int, struct ox_packet_struct *,
			     struct ox_packet_struct *);
int ox_struct_to_packet(struct ox_packet_struct *, char *, int *);
int packet_to_ox_struct(char *, int, struct ox_packet_struct *);
void make_response_packet_template(int connection_id,
				   struct ox_packet_struct *recv_ox_p,
				   struct ox_packet_struct *send_ox_p);
int get_connection(struct ox_packet_struct *);
int delete_connection(int);
int create_new_connection(struct ox_packet_struct *);
int send_ack(int, int, struct ox_packet_struct *);
int send_close_connection(int, int, struct ox_packet_struct *);

#endif				/* __OMEM_H__ */
