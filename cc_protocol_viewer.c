#include <locale.h>
#include <wchar.h>
#include <ncurses.h>
#include <sys/ioctl.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>	// For Ethernet header
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <termios.h>
#include <net/if.h>
#include <sys/socket.h>
#include "ox_common.h"

// Channel A
char * chan_opcode_str[][8] = { "","","","","","","","", //chan 0 - none is valid
	"PUTFULLDATA",  //chan 1 == A
	"PUTPARTIALDATA", 
	"ARITHMETICDATA", 
	"LOGICALDATA", 
	"GET", 
	"INTENT", 
	"ACQUIREBLOCK", 
	"ACQUIREPERM", 
     	"PUTFULLDATA", //chan 2 == B
	"PUTPARTIALDATA",
	"ARITHMETICDATA",
	"LOGICALDATA",
	"GET",
	"INTENT",
	"PROBEBLOCK",
	"PROBEPERM",
	"ACCESSACK", //chan 3 == C
	"ACCESSACKDATA",
	"HINTACK",
	"NOOP",
	"PROBEACK",
	"PROBEACKDATA",
	"RELEASE",
	"RELEASEDATA",
	"ACCESSACK", //chan 4 == D
	"ACCESSACKDATA",
	"HINTACK",
	"NOOP",
	"GRANT",
	"GRANTDATA",
	"RELEASEACK",
	"NOOP",
	"GRANTACK", //chan 5 == E
	};

#define MAX_MAC_LIST 4
uint64_t src_mac[MAX_MAC_LIST] = { 0 };

#define TL_LOG_MAX 1024
#define MSG_LEN 256
struct tl_log_entry {
	int src_id;
	int dst_id;
	int channel;
	char msg[MSG_LEN];
};

int tl_log_current = 0;
struct tl_log_entry tl_log[TL_LOG_MAX];

uint64_t get_host_mac(int id);

void tl_log_add(int src_id, int dst_id, int channel, char* msg)
{
//	printf("%d -> %d chan %d %s\n", src_id, dst_id, channel, msg);
	tl_log[tl_log_current].src_id = src_id;
	tl_log[tl_log_current].dst_id = dst_id;
	tl_log[tl_log_current].channel = channel;
	memset(tl_log[tl_log_current].msg, 0, MSG_LEN);
	strncpy(tl_log[tl_log_current].msg, msg, MSG_LEN);

	tl_log_current ++;
	tl_log_current %= TL_LOG_MAX;
}

int get_tl_log_string(int tl_log_id, char * buf)
{
	if (tl_log_id >= TL_LOG_MAX) {
		sprintf(buf, "tl_log_id %d > TL_LOG_MAX %d", tl_log_id, TL_LOG_MAX);
		return -1;
	}
	if (tl_log[tl_log_id].src_id <= 0 || tl_log[tl_log_id].src_id > MAX_MAC_LIST 
	    || tl_log[tl_log_id].dst_id <= 0 || tl_log[tl_log_id].dst_id  > MAX_MAC_LIST 
	    || get_host_mac(tl_log[tl_log_id].src_id) == 0 || get_host_mac(tl_log[tl_log_id].dst_id) == 0) {
		sprintf(buf, "Empty src %d dst %d", tl_log[tl_log_id].src_id, tl_log[tl_log_id].dst_id);
		return -1;
	}

	if ( tl_log[tl_log_id].src_id < tl_log[tl_log_id].dst_id ) {
		sprintf(buf, "%s", tl_log[tl_log_id].msg);
	} else if ( tl_log[tl_log_id].src_id > tl_log[tl_log_id].dst_id ){
		sprintf(buf, "%s", tl_log[tl_log_id].msg);
	} else { //invalid log
		sprintf(buf, "Empty src %d dst %d", tl_log[tl_log_id].src_id, tl_log[tl_log_id].dst_id);
		return -1;
	}

	return 0;
}

// Get MAC address of a network interface
int get_interface_mac(const char *ifname, uint64_t *mac_addr)
{
    struct ifreq ifr;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
	perror("socket");
	return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
	perror("ioctl SIOCGIFHWADDR");
	close(sock);
	return -1;
    }

    close(sock);

    // Convert MAC address bytes to uint64_t (store in upper 48 bits)
    uint8_t *mac = (uint8_t *)ifr.ifr_hwaddr.sa_data;
    *mac_addr = ((uint64_t)mac[0] << 40) |
		((uint64_t)mac[1] << 32) |
		((uint64_t)mac[2] << 24) |
		((uint64_t)mac[3] << 16) |
		((uint64_t)mac[4] << 8) |
		((uint64_t)mac[5] << 0);

    return 0;
}

void uint64_to_mac_string(uint64_t mac, char *mac_string)
{
    // Extract bytes hi→lo
    uint8_t b5 = (mac >> 40) & 0xFF;
    uint8_t b4 = (mac >> 32) & 0xFF;
    uint8_t b3 = (mac >> 24) & 0xFF;
    uint8_t b2 = (mac >> 16) & 0xFF;
    uint8_t b1 = (mac >> 8) & 0xFF;
    uint8_t b0 = (mac >> 0) & 0xFF;

    // Print as two-digit hex with leading zeros and colon separators
    sprintf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
	    b0, b1, b2, b3, b4, b5);
}

// Parse MAC address string to uint64_t
int mac_string_to_uint64(const char *mac_string, uint64_t *mac)
{
    unsigned int b0, b1, b2, b3, b4, b5;

    if (sscanf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
	       &b0, &b1, &b2, &b3, &b4, &b5) != 6) {
	fprintf(stderr, "Invalid MAC address format. Expected: xx:xx:xx:xx:xx:xx\n");
	return -1;
    }

/*    *mac = ((uint64_t)b0 << 40) |
	   ((uint64_t)b1 << 32) |
	   ((uint64_t)b2 << 24) |
	   ((uint64_t)b3 << 16) |
	   ((uint64_t)b4 << 8) |
	   ((uint64_t)b5 << 0);*/
    *mac = ((uint64_t)b5 << 40) |
	   ((uint64_t)b4 << 32) |
	   ((uint64_t)b3 << 24) |
	   ((uint64_t)b2 << 16) |
	   ((uint64_t)b1 << 8) |
	   ((uint64_t)b0 << 0);


    return 0;
}

void remove_host_id(uint64_t mac)
{
    int i;

    for (i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] == mac) {
	    src_mac[i] = 0;
	    break;
	}
    }

}

void add_host_id(uint64_t mac)
{
    int i;

    for (i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] == 0) {
	    src_mac[i] = mac;
	    break;
	}
    }

}



int get_host_id(uint64_t mac)
{
    int i;


    for (i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] == mac) {
	    return i + 1;
	}
    }

/*    if (i >= MAX_MAC_LIST) {
	for (i = 0; i < MAX_MAC_LIST; i++) {
	    if (src_mac[i] == 0) {
		src_mac[i] = mac;
		return i + 1;
	    }
	}
    }*/

    return -1;
}

uint64_t get_host_mac(int id)
{
    uint64_t mac=0;
    unsigned int b0, b1, b2, b3, b4, b5;

    if ( id > 0 && id <= MAX_MAC_LIST ) {
	mac = src_mac[id - 1];
    	// Extract bytes hi→lo
/*    	b0 = (mac >> 40) & 0xFF;
    	b1 = (mac >> 32) & 0xFF;
    	b2 = (mac >> 24) & 0xFF;
    	b3 = (mac >> 16) & 0xFF;
    	b4 = (mac >> 8) & 0xFF;
    	b5 = (mac >> 0) & 0xFF;

	mac = ((uint64_t)b5 << 40) |
	   	((uint64_t)b4 << 32) |
	   	((uint64_t)b3 << 24) |
	   	((uint64_t)b2 << 16) |
	   	((uint64_t)b1 << 8) |
	   	((uint64_t)b0 << 0);*/
    }
    return mac;
}

void packet_callback(u_char * user, const struct pcap_pkthdr *pkthdr,
		     const u_char * packet)
{
    char buf[2048];
    int packet_len = pkthdr->len;
    struct ox_packet_struct ox_p;
    struct tl_msg_header_chan_AD tl_msg_header;

    uint64_t be64_temp, mask, addr, page_num, cacheline_num;
    int i, data_size;
    int src_host_id = -1, dst_host_id = -1;
    char msg[MSG_LEN];

    memcpy(buf, packet, packet_len);

    //convert TL message header as struct
    packet_to_ox_struct(buf, packet_len, &ox_p);
    if ( ox_p.eth_hdr.eth_type != OX_ETHERTYPE) return;

    if (ox_p.tloe_hdr.msg_type == CLOSE_CONN ){
	if ( get_host_id(ox_p.eth_hdr.src_mac_addr) != 2 ) { //if this is not MEM node
	    remove_host_id(ox_p.eth_hdr.src_mac_addr);
	}
	return;
    } 
    if ( ox_p.tloe_hdr.msg_type == OPEN_CONN ){
	    if ( get_host_id(ox_p.eth_hdr.src_mac_addr) == -1 ) { //if this is not registerd.
		add_host_id(ox_p.eth_hdr.src_mac_addr);
	    }
	    return;
    }

//    printf("src_mac_addr=%012lx dst_mac_addr=%012lx\n", ox_p.eth_hdr.src_mac_addr, ox_p.eth_hdr.dst_mac_addr);
    //get host id with source and destination mac addr
    src_host_id = get_host_id(ox_p.eth_hdr.src_mac_addr);
    if (src_host_id < 0) return;
    dst_host_id = get_host_id(ox_p.eth_hdr.dst_mac_addr);
    if (dst_host_id < 0) return;

    mask = ox_p.tl_msg_mask;
    if (mask) {
	for (i = 0; i < (sizeof(uint64_t) * 8); i++) {
	    if ((mask & 1) == 1) {
		be64_temp = be64toh(ox_p.flits[i]);
		memcpy(&(tl_msg_header), &be64_temp, sizeof(uint64_t));

		//process messages based on channel type
		switch ( tl_msg_header.chan ) {
		case CHANNEL_A:
		case CHANNEL_B:
		case CHANNEL_C:
		    addr = be64toh(ox_p.flits[i + 1]);
		    data_size = 1 << tl_msg_header.size;
		    snprintf(msg, MSG_LEN, "%s 0x%010lx %d", chan_opcode_str[tl_msg_header.chan][tl_msg_header.opcode], addr, data_size);
		    tl_log_add(src_host_id, dst_host_id, tl_msg_header.chan, msg);
		    break;

		case CHANNEL_D:
		    data_size = 1 << tl_msg_header.size;
		    snprintf(msg, MSG_LEN, "%s %d", chan_opcode_str[tl_msg_header.chan][tl_msg_header.opcode], data_size);
		    tl_log_add(src_host_id, dst_host_id, tl_msg_header.chan, msg);
		    break;

		case CHANNEL_E:
		    snprintf(msg, MSG_LEN, "%s", chan_opcode_str[tl_msg_header.chan][tl_msg_header.opcode]);
		    tl_log_add(src_host_id, dst_host_id, tl_msg_header.chan, msg);
		    break;

		default:
//		    printf("UNKNOWN_CHANNEL(chan=%d) %d\n", tl_msg_header.chan, host_id);
		    break;
		}
	    }
	    mask = (mask >> 1);
	    if (mask == 0)
		break;
	}
    }
}

int counter = 0;
int prev_entity_num = 0;
void draw_border(int columns, int rows)
{
    int i, j, k, ret, tl_log_id, msg_num, max_msg;
    uint64_t be_mac;
    int x = 0, y = 0;
    int w = columns - 1;
    int h = rows - 1;
    char mac_string[20];
    char entity_string[20];
    int entity_num = 0;
//    int entity_border_num;
    int entity_border[MAX_MAC_LIST*2];
    char msg[40];

    //Show footer
    mvprintw(y + h - 1, 2, "MECA Memory Cache Coherent Protocol Log\tChannel: ");
    for (i=1; i<=5; i++) {
	attron(COLOR_PAIR(i+1));
	printw("%c", 'A'-1+i);
	attroff(COLOR_PAIR(i+1));
	printw("  ");
    }
    printw("\t\tPress 'q' to exit");

    //find screen vertical diving unit
    for(i=0; i<MAX_MAC_LIST; i++) {
	    if (src_mac[i] != 0 ) entity_num++;
    }
    if ( entity_num != prev_entity_num ) {
	    erase();
    	    refresh();
	    prev_entity_num = entity_num;
    }
//    entity_border_num = entity_num * 2;

    //printw("entity_num=%d ", entity_num);
    for (i=0; i<entity_num+1; i++) {
    	entity_border[i] = i * (w/entity_num);
//	printw("entity_border[%d]=%d ", i, entity_border[i]);
    }

    //Upper left corner
    mvaddch(y, x, ACS_ULCORNER);
    //Upper right corner
    mvaddch(y, x + w, ACS_URCORNER);
    //Lower left corner
    mvaddch(y + h, x, ACS_LLCORNER);
    //Lower right corner
    mvaddch(y + h, x + w, ACS_LRCORNER);
    //Upper horizontal line
    mvhline(y, x + 1, ACS_HLINE, w - 1);
    //Lower horizontal line
    mvhline(y + h, x + 1, ACS_HLINE, w - 1);
    //Left vertical line
    mvvline(y + 1, x, ACS_VLINE, h - 1);
    //Right vertical line
    mvvline(y + 1, x + w, ACS_VLINE, h - 1);

    //Head part
    //Left T 
    mvaddch(y + 2, x, ACS_LTEE);
    //Right T
    mvaddch(y + 2, x + w, ACS_RTEE);
    //Horizontal line
    mvhline(y + 2, x + 1, ACS_HLINE, w - 1);

    //Foot part
    //Left T
    mvaddch(y + h - 2, x, ACS_LTEE);
    //Right T
    mvaddch(y + h - 2, x + w, ACS_RTEE);
    //Horizontal line
    mvhline(y + h - 2, x + 1, ACS_HLINE, w - 1);

    //border between hosts and MECA memory
    for (i=1; i<entity_num; i++) {
    	mvaddch(y + h - 2, entity_border[i], ACS_BTEE);
    	mvaddch(y + 2, entity_border[i], ACS_PLUS);
    	mvvline(y + 3, entity_border[i], ACS_VLINE, h - 5);
    }

    for (i=1; i<entity_num; i++) {
    	mvaddch(y, entity_border[i], ACS_TTEE);
    	mvvline(y + 1, entity_border[i], ACS_VLINE, 1);
    }

    j = 0;
    k = 0; //host num
    for (i=1; i<=MAX_MAC_LIST; i++) {
	    if ( get_host_mac(i) != 0 ) {
		    uint64_to_mac_string(get_host_mac(i), mac_string);
		    if ( i == 2 ) { //MECA MEMORY
			    sprintf(entity_string, "MECA MEM");
			    attron(COLOR_PAIR(7));
			    mvprintw(y + 1, (entity_border[j] + entity_border[j+1])/2 - strlen(entity_string)/2 - 8, "%s", entity_string);
			    attroff(COLOR_PAIR(7));
			    printw("(%s)", mac_string);
		    } else { //Host
			    sprintf(entity_string, "Host %d", k++);
			    attron(COLOR_PAIR(8));
			    mvprintw(y + 1, (entity_border[j] + entity_border[j+1])/2 - strlen(entity_string)/2 - 8, "%s", entity_string);
			    attroff(COLOR_PAIR(8));
			    printw("(%s)", mac_string);
		    }
		    j++;
	    }
    }

    //draw TL msg log
    max_msg = (h/2) - 3;
    if ( max_msg < 0 ) max_msg = 0;
    i = max_msg;
    msg_num = 0;
    while (max_msg > msg_num && i > 0) {
	    tl_log_id = (tl_log_current-i)%TL_LOG_MAX;
	    ret = get_tl_log_string(tl_log_id, msg);
	    if (ret == 0 ) {
		int entity_border_id = tl_log[tl_log_id].src_id;
		//clear other part
		for (j=0;j<entity_num; j++) {
		       move(4+(msg_num)*2, entity_border[j] + 1);
		       for (k=0; k<(w/entity_num-1); k++) addch(' ');
		}

		mvprintw(4+(msg_num)*2, 1, "%04d", tl_log_id);
		if ( tl_log[tl_log_id].src_id > tl_log[tl_log_id].dst_id ) {
			mvprintw(4+(msg_num)*2, entity_border[entity_border_id-1] - 1, "<-- ");
			attron(COLOR_PAIR(tl_log[tl_log_id].channel+1));
			printw("%s", msg);
			attroff(COLOR_PAIR(tl_log[tl_log_id].channel+1));
		} else {
			attron(COLOR_PAIR(tl_log[tl_log_id].channel+1));
			mvprintw(4+(msg_num)*2, entity_border[entity_border_id] - 2 - strlen(msg), "%s", msg);
			attroff(COLOR_PAIR(tl_log[tl_log_id].channel+1));
			printw(" -->");

		}

		msg_num++;
	    }
	    i--;
    }

}


int prev_columns = 0, prev_rows = 0;

void draw_screen(void)
{
    struct winsize ts;
    int columns = 0, rows = 0;
    int block_count = 0;
    int block_unit_shift = 0;
    size_t i;
    char block_size_string[16];
    int row_start = 11;
    uint64_t touched_page_num = 0;

    //get screen resolution
    ioctl(0, TIOCGWINSZ, &ts);
    columns = ts.ws_col;
    rows = ts.ws_row;
    
    if ( prev_columns != columns || prev_rows != rows ) {
	    erase();
    	    refresh();
	    prev_columns = columns;
	    prev_rows = rows;
    }

    draw_border(columns, rows);

    //show screen
    refresh();
}

void *status_update_thread(void *data)
{
	int interval_usec, bytes;
	char ch;
	int flags;
	struct termios t;

	interval_usec = *((int *) data);

	flags = fcntl(STDIN_FILENO, F_GETFL, 0);
	fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
	tcgetattr(STDIN_FILENO, &t);
	t.c_lflag &= ~(ICANON | ECHO);
	tcsetattr(STDIN_FILENO, TCSANOW, &t);


	while(1) {

		draw_screen();
		
		usleep(interval_usec);
		//read key input
	bytes = read(STDIN_FILENO, &ch, 1);
	if (bytes > 0) {
		if (ch == 'q') { //terminate program
		    endwin();
		    exit(0);
		}
	}

	}

}


void handleCtrlC(int signum)
{
    endwin();
    exit(0);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pthread_t pid;
    int interval_usec = 100000;	//0.1 sec
    uint64_t mem_mac = 0;
    int host_id;
    char mac_string[18];
    int i;
    char *dev;

    if (argc < 4) {
	printf("Usage: %s [interface] [--mem_mac xx:xx:xx:xx:xx:xx]\n", argv[0]);
	return 0;
    }

    // Parse arguments
    dev = argv[1];

    // Parse optional arguments
    for (i = 2; i < argc; i++) {
	if (strcmp(argv[i], "--mem_mac") == 0) {
	    if (i + 1 < argc) {
		if (mac_string_to_uint64(argv[i + 1], &mem_mac) < 0) {
		    fprintf(stderr, "Failed to parse memory MAC address\n");
		    return 1;
		}
		i++;  // Skip the MAC address argument
	    } else {
		fprintf(stderr, "--mem_mac requires a MAC address argument\n");
		return 1;
	    }
	}
    }

    signal(SIGINT, handleCtrlC);

    // Register memory MAC address
    if (mem_mac != 0) {
	src_mac[1] = mem_mac;
	host_id = get_host_id(mem_mac);
	uint64_to_mac_string(mem_mac, mac_string);
	printf("Memory MAC: %s, Host ID: %d\n", mac_string, host_id);
    }

    memset(tl_log,0, sizeof(struct tl_log_entry)*TL_LOG_MAX);

    //init screen and color pairs
    setlocale(LC_ALL, "C-UTF-8");
    initscr();
    start_color();

    init_pair(1, COLOR_WHITE, COLOR_BLACK);             //Initial state
    init_pair(2, COLOR_WHITE, COLOR_RED);
    init_pair(3, COLOR_WHITE, COLOR_BLUE);
    init_pair(4, COLOR_BLACK, COLOR_WHITE);
    init_pair(5, COLOR_BLACK, COLOR_GREEN);
    init_pair(6, COLOR_BLACK, COLOR_MAGENTA);
    init_pair(7, COLOR_RED, COLOR_BLACK);	//MECA Mem
    init_pair(8, COLOR_GREEN, COLOR_BLACK);	//Host

    if (pthread_create(&pid, NULL, status_update_thread, (void *) &interval_usec)) {
	    perror("Thread create error.");
	    exit(0);
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
	return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_callback, NULL);

    pcap_close(handle);

    endwin();
    return 0;
}
