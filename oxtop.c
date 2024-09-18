#include <locale.h>
#include <wchar.h>
#include <ncurses.h>
#include <sys/ioctl.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h> // For Ethernet header
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include "ox_common.h"

/**
 * @brief Print payload in Hex format
 */
void print_payload(char *data, int size) {
	int i, j;

    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) {
            printf("\t"); 
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] < 128)
                    printf("%c", (unsigned char)data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }

	if ( (i % 8) == 0 && (i % 16) != 0 ) printf(" ");
        printf(" %02X", (unsigned char) data[i]);		// print DATA

        if (i == size - 1) {
            for (j = 0; j < (15 - (i % 16)); j++)
                printf("   ");

            printf("\t");

            for (j = (i - (i % 16)); j <= i; j++) {
                if (data[j] >= 32 && data[j] < 128)
                    printf("%c", (unsigned char) data[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}


#define TOUCHED (0x1<<0)
#define READ (0x1<<1)
#define WRITE (0x1<<2)

//int count=0;
uint64_t base_addr = 0x200000000, size=8192ULL*1024*1024;
int * total_access_counter_array = NULL;
int * access_record_array = NULL;
uint64_t total_page_num = 0;

void draw_border(int columns, int rows, char * block_size)
{
    int x=0, y=0;
    int w = columns-1;
    int h = rows-1;

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

    //Show Title
    mvprintw(1, 2, "MECA Memory Access Monitor");
    printw("\t\t");
    addch(' '|A_REVERSE);
    printw(" = %s", block_size);
}

void draw_status(int * status_array, int count, int row_width)
{
	int row = 4;
	int current = 0;

    	move(row, 2);
	do {
            if ( (status_array[current] & 0x6) == READ ) {
		    addch('R'|COLOR_PAIR(1));
	    } else if ( (status_array[current] & 0x6) == WRITE ) {
		    addch('W'|COLOR_PAIR(2));
	    } else if ( (status_array[current] & 0x6) == (READ|WRITE) ) {
		    addch('M'|COLOR_PAIR(3));
	    } else if ( (status_array[current] & 0x1) == TOUCHED ) {
//		    addch(' '|A_REVERSE);
		    addch(' '|COLOR_PAIR(4));
	    } else {
		    addch(ACS_BULLET);
	    }

	    current++;
	    if ( current % row_width == 0 ) {
		    row++;
		    move(row, 2);
	    }
	} while(current < count);
	move (0, 0);
}

void draw_screen(void)
{
    struct winsize ts;
    int columns = 0, rows = 0;
    int block_count = 0;
    int block_unit_shift = 0;
    int * status_array;
    size_t i;
    char block_size_string[16];
    
    //get screen resolution
    ioctl(0, TIOCGWINSZ, &ts);
    columns = ts.ws_col;
    rows = ts.ws_row;

    //How many block to use for display
    block_count = (columns - 2) * (rows - 4);

    while ( (total_page_num >> block_unit_shift) > block_count ) {
        block_unit_shift ++;
    }

//printf("block_unit_shift = %d\n", block_unit_shift);
    block_count = total_page_num >> block_unit_shift;

    //make block unit string (ex. "4 kB")

    if ( block_unit_shift < 8 ) sprintf(block_size_string, "%d kB", 4<<block_unit_shift);
    else if ( block_unit_shift < 18 ) sprintf(block_size_string, "%d MB", 1<<(2+block_unit_shift-10));
    else if ( block_unit_shift < 28 ) sprintf(block_size_string, "%d GB", 1<<(2+block_unit_shift-20));

    //draw border and title
    draw_border(columns, rows, block_size_string);

    //Make status array and fill it with access_record_array
    status_array = malloc(sizeof(int)*block_count);
    bzero(status_array, sizeof(int)*block_count);

    for (i=0; i<total_page_num; i++) {
	status_array[i>>block_unit_shift] |= (access_record_array[i] & (READ|WRITE|TOUCHED));
    }
    
    //draw latest access status
    draw_status(status_array, block_count, columns - 4);

    refresh();

    free(status_array);
}

time_t last_time = 0;

void packet_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    char buf[2048];
    int packet_len = pkthdr->len;
    struct ox_packet_struct ox_p;
    struct tl_msg_header_chan_AD tl_msg_header;

    uint64_t be64_temp, mask, addr, page_num;
    int i, size, updated=0;

    time_t now;

    memcpy(buf, packet, packet_len);

    //convert TL message header as struct
    packet_to_ox_struct(buf, packet_len, &ox_p);

    mask = ox_p.tl_msg_mask;
    if ( mask ) {
	for(i=0;i<(sizeof(uint64_t)*8);i++) {
		if ( mask == 0 ) break;

		if ( (mask & 1) == 1) {
			be64_temp = be64toh(ox_p.flits[i]);
			memcpy(&(tl_msg_header), &be64_temp, sizeof(uint64_t));

			if ( tl_msg_header.chan == CHANNEL_A ) {
				addr = be64toh(ox_p.flits[i+1]);
				size = 1<<tl_msg_header.size;
				page_num = (addr-base_addr)>>12;
				total_access_counter_array[page_num]++;
				if ( page_num >= total_page_num ) {
					printf("addr = %lx is out of range.\n", addr);
					continue;
				}

				if ( tl_msg_header.opcode == A_PUTFULLDATA_OPCODE ) {
					access_record_array[page_num] |= WRITE;
					access_record_array[page_num] |= TOUCHED;
				} else if ( tl_msg_header.opcode == A_GET_OPCODE ) {
					access_record_array[page_num] |= READ;
				}
			}
		}
		mask = (mask >> 1);
	}
    }
}

void * status_update_thread(void * data)
{
	int interval_usec, i;

	interval_usec = *((int *) data);

    	initscr();
	start_color();

	init_color(1, 0, 1000, 0); //GREEN
	init_color(2, 1000, 0, 0); //RED
	init_color(3, 1000, 1000, 0); //YELLOW
	init_color(4, 0, 0, 1000); //BLUE
	init_color(5, 1000, 1000, 1000); //WHITE
	init_color(6, 500, 500, 500); //GRAY
	init_color(7, 0, 0, 0); //BLACK
	init_pair(1, 1, 4); //Green character on Blue background, READ
	init_pair(2, 2, 4); //Red character on Blue background, WRITE
	init_pair(3, 3, 4); //Yellow character on Blue background, MIXED
	init_pair(4, 6, 7); //White character on Gray background, TOUCHED

	while(1) {
//		printf( "This is thread.\n");
		draw_screen();
	    for(i=0; i<total_page_num; i++) {
		    access_record_array[i] &= ~(READ|WRITE);
	    }

	    usleep(interval_usec);
	}
}

void handleCtrlC(int signum)
{
	endwin();
	exit(0);
}

int main(int argc, char** argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const char *dev = "enp179s0"; // Change this to your desired interface
    pthread_t pid;
    int interval_usec = 500000; //0.5 sec

    if (argc < 2) {
	    printf("Usage: %s [interface] [size in MB, default=8192] [base address, default=0x200000000]\n", argv[0]);
	    return 0;
    }

    if ( argc >= 2 ) dev = argv[1];
    if ( argc >= 3 ) size = atoi(argv[2])*1024*1024ULL;
    if ( argc >= 4 ) base_addr = strtoull(argv[3], NULL, 16);

    signal(SIGINT, handleCtrlC);

    printf("size = %lu base_addr = 0x%lx\n", size, base_addr);

    total_page_num = size/4096;
    total_access_counter_array = malloc(sizeof(int)*total_page_num);
    bzero(total_access_counter_array, sizeof(int)*total_page_num);
    access_record_array = malloc(sizeof(int)*total_page_num);
    bzero(access_record_array, sizeof(int)*total_page_num);

    setlocale(LC_ALL, "C-UTF-8");
    draw_screen();

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return 1;
    }

    if (pthread_create( &pid, NULL, status_update_thread, (void*)&interval_usec))
    {
	    perror("Thread create error.");
	    exit (0);
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_callback, NULL);

    pcap_close(handle);

    endwin();
    return 0;
}

