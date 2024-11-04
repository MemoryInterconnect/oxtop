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
#include "ox_common.h"

//access_bit definition
#define TOUCHED (0x1<<0)
#define READ (0x1<<1)
#define WRITE (0x1<<2)

typedef struct {
	short access_bit;
	short host_id;
	short hotness;
} access_record;

#define MAX_MAC_LIST 4
uint64_t src_mac[MAX_MAC_LIST] = {0};

uint64_t base_addr = 0x200000000, size = 8192ULL * 1024 * 1024;
int *total_read_counter_array = NULL;
int *total_write_counter_array = NULL;
access_record * access_record_array = NULL;
uint64_t total_page_num = 0;
size_t total_read_bytes = 0, total_write_bytes = 0;

int get_host_id(uint64_t mac)
{
	int i;

	for(i = 0; i<MAX_MAC_LIST; i++) {
	    if (src_mac[i] == mac) {
		    return i+1;
	    }
	}

	if ( i >= MAX_MAC_LIST ) {
		for(i=0 ; i<MAX_MAC_LIST; i++) {
			if (src_mac[i] == 0) {
				src_mac[i] = mac;
				return i+1;
			}
		}
	}

	return -1;
}

void draw_border(int columns, int rows, char *block_size, char * bandwidth_string)
{
    int i;
    uint64_t be_mac;
    int x = 0, y = 0;
    int w = columns - 1;
    int h = rows - 1;

    //Show Title
    mvprintw(1, 2, "MECA Memory Access Monitor");
    printw("\t\t");
    addch(' ' | A_REVERSE);
    printw(" = %s", block_size);
    printw("\t\tPress 'c' to clear\t\tPress 'q' to exit");

    //Show MAC of hosts
    mvprintw(y + h - 1, 2, "Host MACs\t\t");
    for(i=0; i<4; i++) {
	    if (src_mac[i] != 0) {
		    be_mac = __builtin_bswap64(src_mac[i]);
		    be_mac >>= 16;
	            addch(ACS_BULLET | COLOR_PAIR(4 + i));
		    printw(" = %lx\t", be_mac);
	    } 
    }
    printw("%s          ", bandwidth_string);

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

}

//void draw_status(int *status_array, int count, int row_width)
void draw_status(access_record *status_array, int count, int row_start, int row_end, int block_unit)
{
    int row = 4;
    long unsigned int current = 0;
    int host_id = 0;

    move(row, 1);
    printw("%09lx", current*block_unit);
    move(row, row_start);
    do {
	if ( status_array[current].host_id > 0 ) {
	    host_id = status_array[current].host_id;
	    if ((status_array[current].access_bit & 0x6) == READ) {
	    	addch('R' | COLOR_PAIR(2));
	    } else if ((status_array[current].access_bit & 0x6) == WRITE) {
	    	addch('W' | COLOR_PAIR(2));
	    } else if ((status_array[current].access_bit & 0x6) == (READ | WRITE)) {
	    	addch('M' | COLOR_PAIR(2));
	    } else if ( status_array[current].hotness > 0 ) {
		    addch(ACS_BULLET | COLOR_PAIR(3));
	    } else if ((status_array[current].access_bit & 0x1) == TOUCHED) {
		    addch(ACS_BULLET | COLOR_PAIR(3 + host_id));
	    } else addch(ACS_BULLET|COLOR_PAIR(1));
	} else {
	    addch(ACS_BULLET|COLOR_PAIR(1));
	}

	current++;
	if (current % (row_end-row_start) == 0) {
	    row++;
	    move(row, 1);
    	    printw("%09lx", current*block_unit);
	    move(row, row_start);
	}
    } while (current < count);
    move(0, 0);
}

int prev_columns = 0, prev_rows = 0;

void draw_screen(char * bandwidth_string)
{
    struct winsize ts;
    int columns = 0, rows = 0;
    int block_count = 0;
    int block_unit_shift = 0;
    access_record *status_array;
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

    //How many block to use for display
    block_count = (columns - row_start) * (rows - 4);

    while ((total_page_num >> block_unit_shift) > block_count) {
	block_unit_shift++;
    }

    block_count = total_page_num >> block_unit_shift;

    //make block unit string (ex. "4 kB")
    if (block_unit_shift < 8)
	sprintf(block_size_string, "%d kB", 4 << block_unit_shift);
    else if (block_unit_shift < 18)
	sprintf(block_size_string, "%d MB",
		1 << (2 + block_unit_shift - 10));
    else if (block_unit_shift < 28)
	sprintf(block_size_string, "%d GB",
		1 << (2 + block_unit_shift - 20));

    //draw border and title
    draw_border(columns, rows, block_size_string, bandwidth_string);

    //Make status array and fill it with access_record_array
    status_array = malloc(sizeof(access_record) * block_count);
    bzero(status_array, sizeof(access_record) * block_count);

    //Distill access_record_array to status_array for screen representation
    for (i = 0; i < total_page_num; i++) {
	if ( access_record_array[i].host_id == 0 
			&& access_record_array[i].access_bit == 0 
			&& access_record_array[i].hotness == 0) 
		continue;

	if ( access_record_array[i].hotness > status_array[i >> block_unit_shift].hotness ) {
		status_array[i >> block_unit_shift].hotness = access_record_array[i].hotness;
	}

	if ( access_record_array[i].hotness > 0 ) {
		access_record_array[i].hotness--;
	}

	if ( status_array[i >> block_unit_shift].host_id == 0 && access_record_array[i].host_id != 0)
		status_array[i >> block_unit_shift].host_id = access_record_array[i].host_id;

	if ( access_record_array[i].access_bit & TOUCHED ) touched_page_num++;

	status_array[i >> block_unit_shift].access_bit |=
	    (access_record_array[i].access_bit & (READ | WRITE | TOUCHED));
    }

    //draw latest access status
    draw_status(status_array, block_count, row_start, columns - 2, 1<<(block_unit_shift+12));

    //show screen
    refresh();

    free(status_array);
}

void packet_callback(u_char * user, const struct pcap_pkthdr *pkthdr,
		     const u_char * packet)
{
    char buf[2048];
    int packet_len = pkthdr->len;
    struct ox_packet_struct ox_p;
    struct tl_msg_header_chan_AD tl_msg_header;

    uint64_t be64_temp, mask, addr, page_num;
    int i, data_size;
    int host_id = -1;

    memcpy(buf, packet, packet_len);

    //convert TL message header as struct
    packet_to_ox_struct(buf, packet_len, &ox_p);

    mask = ox_p.tl_msg_mask;
    if (mask) {
	for (i = 0; i < (sizeof(uint64_t) * 8); i++) {
	    if ((mask & 1) == 1) {
		be64_temp = be64toh(ox_p.flits[i]);
		memcpy(&(tl_msg_header), &be64_temp, sizeof(uint64_t));

		//if this is a channel A message, get address and size
		if (tl_msg_header.chan == CHANNEL_A) {
		    
		    addr = be64toh(ox_p.flits[i + 1]);
		    if ( (addr < base_addr) || (addr > base_addr+size)  ) {
//			    printf("received addr 0x%lx is invalid. base_addr = 0x%lx size=0x%lx\n", addr, base_addr, size);
			    break;
		    }

		    //get host id with source mac addr
		    host_id = get_host_id(ox_p.eth_hdr.src_mac_addr);
		    if ( host_id < 0 ) {
//			    printf("macaddr = %lx is not in host_mac_addr list.\n", ox_p.eth_hdr.src_mac_addr);
			    break;
		    }

		    page_num = (addr - base_addr) >> 12;

		    access_record_array[page_num].host_id = host_id;

		    if (page_num < total_page_num) {

			data_size = 1 << tl_msg_header.size;

			if (tl_msg_header.opcode == A_PUTFULLDATA_OPCODE) {
			    total_write_counter_array[page_num]++;
			    access_record_array[page_num].access_bit |= WRITE;
			    access_record_array[page_num].access_bit |= TOUCHED;
			    total_write_bytes += data_size;
			    //Hotness 
			    access_record_array[page_num].hotness = 5;
			} else if (tl_msg_header.opcode == A_GET_OPCODE) {
			    total_read_counter_array[page_num]++;
			    access_record_array[page_num].access_bit |= READ;
			    total_read_bytes += data_size;
			    //Hotness 
			    access_record_array[page_num].hotness = 5;
			}
		    } else {
			printf("addr = %lx is out of range.\n", addr);
		    }
		}
	    }
	    mask = (mask >> 1);
	    if (mask == 0)
		break;
	}
    }
}

void *status_update_thread(void *data)
{
    int interval_usec, i;
    int flags;
    struct termios t;
    ssize_t bytes;
    char ch;
    size_t prev_read_bytes = 0, prev_write_bytes = 0;
    size_t current_read_bytes = 0, current_write_bytes = 0;
    float elapsed_seconds = 0;
    char bandwidth_string[256] = {'\0'};
    struct timeval prev_tv, current_tv;
    float time_diff;

    interval_usec = *((int *) data);

    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    tcgetattr(STDIN_FILENO, &t);
    t.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t);
    bzero(&prev_tv, sizeof(struct timeval));

    while (1) {
    	//Calculate R/W Bandwidth
	gettimeofday(&current_tv, NULL);
	time_diff = (float)(current_tv.tv_sec - prev_tv.tv_sec) + 0.000001*(current_tv.tv_usec - prev_tv.tv_usec);
	memcpy(&prev_tv, &current_tv, sizeof(struct timeval));
	
    	current_read_bytes = total_read_bytes - prev_read_bytes;
	current_write_bytes = total_write_bytes - prev_write_bytes;
	prev_read_bytes = total_read_bytes;
	prev_write_bytes = total_write_bytes;

	sprintf(bandwidth_string, "bandwidth R %.1fMB/s | W %.1fMB/s", 
		(float)current_read_bytes/1048576/time_diff, (float)current_write_bytes/1048576/time_diff);

	//display status
	draw_screen(bandwidth_string);

	usleep(interval_usec);

	//clear previous access records
	for (i = 0; i < total_page_num; i++) {
	    access_record_array[i].access_bit &= ~(READ | WRITE);
	}

	//read key input
	bytes = read(STDIN_FILENO, &ch, 1);
	if (bytes > 0) {
		if (ch == 'c') {//clear status
		    bzero(access_record_array, total_page_num*sizeof(access_record));
		    bzero(src_mac, sizeof(uint64_t)*MAX_MAC_LIST);
	    	    clear();
    	            refresh();
	    	}
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
    const char *dev = "enp179s0";	// Change this to your desired interface
    pthread_t pid;
    int interval_usec = 500000;	//0.5 sec

    if (argc < 2) {
	printf
	    ("Usage: %s [interface] [size in MB, default=8192] [base address, default=0x200000000]\n",
	     argv[0]);
	return 0;
    }

    if (argc >= 2)
	dev = argv[1];
    if (argc >= 3)
	size = atoi(argv[2]) * 1024 * 1024ULL;
    if (argc >= 4)
	base_addr = strtoull(argv[3], NULL, 16);

    signal(SIGINT, handleCtrlC);

    printf("size = %lu base_addr = 0x%lx\n", size, base_addr);

    total_page_num = size / 4096;
    total_read_counter_array = malloc(sizeof(int) * total_page_num);
    total_write_counter_array = malloc(sizeof(int) * total_page_num);
    bzero(total_read_counter_array, sizeof(int) * total_page_num);
    bzero(total_write_counter_array, sizeof(int) * total_page_num);
//    access_record_array = malloc(sizeof(int) * total_page_num);
    access_record_array = malloc(sizeof(access_record) * total_page_num);
    bzero(access_record_array, sizeof(access_record) * total_page_num);

    setlocale(LC_ALL, "C-UTF-8");
    initscr();
    start_color();

    init_pair(1, COLOR_WHITE, COLOR_BLACK);		//Normal state
    init_pair(2, COLOR_WHITE, COLOR_RED);		//Read/Write
    init_pair(3, COLOR_BLACK, COLOR_YELLOW);		//Hot
    init_pair(4, COLOR_WHITE, COLOR_BLUE);		//Host 0, Mixed and no action
    init_pair(5, COLOR_WHITE, COLOR_MAGENTA);		//Host 1, Mixed and no action
    init_pair(6, COLOR_BLACK, COLOR_GREEN);		//Host 2, Mixed and no action
    init_pair(7, COLOR_BLACK, COLOR_CYAN);		//Host 3, Mixed and no action

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
	return 1;
    }

    if (pthread_create
	(&pid, NULL, status_update_thread, (void *) &interval_usec)) {
	perror("Thread create error.");
	exit(0);
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_callback, NULL);

    pcap_close(handle);

    endwin();
    return 0;
}
