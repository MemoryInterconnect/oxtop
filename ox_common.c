#include <stdio.h>
#include <endian.h>
#include <string.h>
#include <netinet/in.h>
#include "ox_common.h"

struct ox_connection ox_conn_list[NUM_CONNECTION];

/**
 * @brief Return connection ID with a matching source mac address 
 * @param ox_packet_structure
 * @return conntction id
 */
int get_connection(struct ox_packet_struct *ox_p)
{
    int i;

    if (!ox_p)
	return -1;

    for (i = 0; i < NUM_CONNECTION; i++) {
	if (ox_conn_list[i].src_mac_addr == ox_p->eth_hdr.src_mac_addr) {
	    //If received seq_num is older than last seq_num_expected. ignore the packet.
/*			if( ox_conn_list[i].seq_num_expected > ox_p->tloe_hdr.seq_num ) { 
//				printf("arrived seq_num %d is older than seq_num_expected %d.\n", ox_p->tloe_hdr.seq_num, ox_conn_list[i].seq_num_expected);
				return -1;
			}
*/
	    if (ox_conn_list[i].seq_num_expected <= ox_p->tloe_hdr.seq_num)
		//update seq_num_expected.
		ox_conn_list[i].seq_num_expected =
		    ox_p->tloe_hdr.seq_num + 1;

//                      printf("seq_num_expected %d | my seq_num %d\n", ox_conn_list[i].seq_num_expected, ox_conn_list[i].seq_num);
	    return i;
	}
    }
    printf("Connection Error! - MAC %lx is not found in list.\n",
	   be64toh(ox_p->eth_hdr.src_mac_addr) >> 16);

    return -1;
}

/**
 * @brief Delete connection ID with a matching source mac address
 * @return 0 : success
 */
int delete_connection(int connection_id)
{
    ox_conn_list[connection_id].src_mac_addr = 0;

    return 0;
}

/**
 * @brief Create new connection for msg type 2(Open_connection)
 * @return Index num., -1 : error
 */
int create_new_connection(struct ox_packet_struct *ox_p)
{
    int i;

    if (!ox_p)
	return -1;
    if (ox_p->tloe_hdr.seq_num != 0) {
	printf("seq_num=%d must be 0 for Open Connection packet.\n",
	       ox_p->tloe_hdr.seq_num);
	return -1;
    }
    //check if same mac is already registered, overwrite it.
    for (i = 0; i < NUM_CONNECTION; i++) {
	if (ox_conn_list[i].src_mac_addr == ox_p->eth_hdr.src_mac_addr) {
	    ox_conn_list[i].seq_num = 0;
	    ox_conn_list[i].seq_num_expected = ox_p->tloe_hdr.seq_num + 1;
	    ox_conn_list[i].credit = 10;
	    return i;
	}
    }

    if (i == NUM_CONNECTION) {	//If there is no match, find an empty slot and create new connection
	for (i = 0; i < NUM_CONNECTION; i++) {
	    if (ox_conn_list[i].src_mac_addr == 0) {
		ox_conn_list[i].src_mac_addr = ox_p->eth_hdr.src_mac_addr;
		ox_conn_list[i].seq_num = 0;
		ox_conn_list[i].seq_num_expected =
		    ox_p->tloe_hdr.seq_num + 1;
		ox_conn_list[i].credit = 10;
		//If creation success, return index.
		return i;
	    }
	}
    }
    //If there is no empty slot, return error.
    return -1;
}

/**
 *
 */
void build_ethernet_header(struct ox_packet_struct *recv_ox_p,
			   struct ox_packet_struct *send_ox_p)
{
    send_ox_p->eth_hdr.dst_mac_addr = recv_ox_p->eth_hdr.src_mac_addr;
    send_ox_p->eth_hdr.src_mac_addr = recv_ox_p->eth_hdr.dst_mac_addr;
    send_ox_p->eth_hdr.eth_type = recv_ox_p->eth_hdr.eth_type;
}

/**
 *
 */
void build_tLoE_frame_header(int connection_id,
			     struct ox_packet_struct *recv_ox_p,
			     struct ox_packet_struct *send_ox_p)
{
    send_ox_p->tloe_hdr.credit = ox_conn_list[connection_id].credit;
    send_ox_p->tloe_hdr.chan = recv_ox_p->tloe_hdr.chan;
    send_ox_p->tloe_hdr.ack = ACK;
    send_ox_p->tloe_hdr.seq_num_ack = recv_ox_p->tloe_hdr.seq_num;
    send_ox_p->tloe_hdr.seq_num = (ox_conn_list[connection_id].seq_num)++;
    send_ox_p->tloe_hdr.msg_type = NORMAL;	//Normal type
    send_ox_p->tloe_hdr.vc = recv_ox_p->tloe_hdr.vc;
}


void make_response_packet_template(int connection_id,
				   struct ox_packet_struct *recv_ox_p,
				   struct ox_packet_struct *send_ox_p)
{
    send_ox_p->eth_hdr.dst_mac_addr = recv_ox_p->eth_hdr.src_mac_addr;
    send_ox_p->eth_hdr.src_mac_addr = recv_ox_p->eth_hdr.dst_mac_addr;
    send_ox_p->eth_hdr.eth_type = recv_ox_p->eth_hdr.eth_type;

    send_ox_p->tloe_hdr.chan = recv_ox_p->tloe_hdr.chan;
    send_ox_p->tloe_hdr.seq_num_ack = recv_ox_p->tloe_hdr.seq_num;
    send_ox_p->tloe_hdr.credit = ox_conn_list[connection_id].credit;
    send_ox_p->tloe_hdr.seq_num = ox_conn_list[connection_id].seq_num++;
    send_ox_p->tloe_hdr.ack = 1;
    send_ox_p->tloe_hdr.msg_type = NORMAL;	//Normal type
    send_ox_p->tloe_hdr.vc = recv_ox_p->tloe_hdr.vc;

}

/**
 * @brief
 */
int send_ack(int sockfd, int connection_id,
	     struct ox_packet_struct *recv_ox_p)
{
    char send_buffer[RECV_BUFFER_SIZE] = { 0, };
    int send_buffer_size = 0;
    struct ox_packet_struct send_ox_p;

    bzero(&send_ox_p, sizeof(struct ox_packet_struct));
    make_response_packet_template(connection_id, recv_ox_p, &send_ox_p);

    send_ox_p.tloe_hdr.chan = 1;	//CHAN A

    ox_struct_to_packet(&send_ox_p, send_buffer, &send_buffer_size);

#if 0
    PRINT_LINE("----------------   SEND   ----------------\n");
    print_payload(send_buffer, send_buffer_size);
    printf("------------------------------------------\n\n");
#endif
    send(sockfd, send_buffer, send_buffer_size, 0);

    return 0;

}



/**
 * @brief
 */
int send_close_connection(int sockfd, int connection_id,
			  struct ox_packet_struct *recv_ox_p)
{
    char send_buffer[RECV_BUFFER_SIZE] = { 0, };
    int send_buffer_size = 0;
    struct ox_packet_struct send_ox_p;

    bzero(&send_ox_p, sizeof(struct ox_packet_struct));

    make_response_packet_template(connection_id, recv_ox_p, &send_ox_p);
    send_ox_p.tloe_hdr.msg_type = 3;	//close connection

    ox_struct_to_packet(&send_ox_p, send_buffer, &send_buffer_size);

#if 0
    PRINT_LINE("----------------   SEND   ----------------\n");
    print_payload(send_buffer, send_buffer_size);
    printf("------------------------------------------\n\n");
#endif
    send(sockfd, send_buffer, send_buffer_size, 0);

    return 0;

}

/**
 * @brief Convert an omnixtend structure to packet format
 */
int ox_struct_to_packet(struct ox_packet_struct *ox_p, char *send_buffer,
			int *send_buffer_size)
{
    int packet_size = 0;
    uint64_t mask;
    uint64_t be64_temp;
    int offset = 0;

    if (ox_p->flit_cnt < 5) {	//at minimum. packet_size must be 70
	packet_size +=
	    (sizeof(struct eth_header) + sizeof(struct tloe_header) +
	     (sizeof(uint64_t) * 5) + sizeof(ox_p->tl_msg_mask));
    } else {
	packet_size +=
	    (sizeof(struct eth_header) + sizeof(struct tloe_header) +
	     (sizeof(uint64_t) * ox_p->flit_cnt) +
	     sizeof(ox_p->tl_msg_mask));
    }

    bzero((void *) send_buffer, packet_size);

    // Ethernet Header
    memcpy(send_buffer, &(ox_p->eth_hdr), sizeof(struct eth_header));
    offset += sizeof(struct eth_header);

    // TLoE frame Header
    be64_temp = htobe64(*(uint64_t *) & (ox_p->tloe_hdr));
    memcpy(send_buffer + offset, &be64_temp, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    if (ox_p->flit_cnt > 0 && ox_p->flits != NULL) {
	memcpy(send_buffer + offset, ox_p->flits,
	       sizeof(uint64_t) * ox_p->flit_cnt);
	PRINT_LINE("ox_p->flits[0]=0x%lx\n", ox_p->flits[0]);
    }
    // TLoE frame mask
    mask = htobe64(ox_p->tl_msg_mask);
    memcpy(send_buffer + packet_size - sizeof(uint64_t), &mask,
	   sizeof(uint64_t));

    *send_buffer_size = packet_size;

    return 0;
}

/**
 * @brief Change the packet to an omnixtend structure
 */
int packet_to_ox_struct(char *recv_buffer, int recv_size,
			struct ox_packet_struct *ox_p)
{
    uint64_t tl_msg_mask = 0;
    uint64_t tloe_hdr = 0;
    int tl_msg_full_count_by_8bytes = 0;
    struct eth_header *recv_packet_eth_hdr;
    struct tloe_header *recv_packet_tloe_hdr;

    struct tl_msg_header_chan_AD __tl_msg_hdr = { 0, };
    uint64_t temp_tl_msg_hdr =
	*(uint64_t *) (recv_buffer + sizeof(struct eth_header) +
		       sizeof(struct tloe_header));
    *(uint64_t *) & __tl_msg_hdr = be64toh(temp_tl_msg_hdr);

    // Ethernet MAC header (14 bytes)
    recv_packet_eth_hdr = (struct eth_header *) recv_buffer;

    memcpy(&(ox_p->eth_hdr), recv_packet_eth_hdr,
	   sizeof(struct eth_header));

    // TLoE frame header (8 bytes)
    recv_packet_tloe_hdr =
	(struct tloe_header *) (recv_buffer + sizeof(struct eth_header));
    tloe_hdr = be64toh(*(uint64_t *) recv_packet_tloe_hdr);
    memcpy(&(ox_p->tloe_hdr), &tloe_hdr, sizeof(uint64_t));

    // TileLink messages (8 bytes * n)
    tl_msg_full_count_by_8bytes =
	(recv_size - sizeof(struct eth_header) -
	 sizeof(struct tloe_header) -
	 sizeof(uint64_t) /*mask */ ) / sizeof(uint64_t);
    ox_p->flit_cnt = tl_msg_full_count_by_8bytes;

    // just pass the pointer of receive buffer
    ox_p->flits =
	(uint64_t *) (recv_buffer + sizeof(struct eth_header) +
		      sizeof(struct tloe_header));

    // TLoE frame mask (8 bytes)
    memcpy(&tl_msg_mask, recv_buffer + recv_size - sizeof(tl_msg_mask),
	   sizeof(tl_msg_mask));
    ox_p->tl_msg_mask = be64toh(tl_msg_mask);

    return 0;
}
