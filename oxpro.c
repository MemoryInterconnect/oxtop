#include <locale.h>
#include <wchar.h>
#include <ncurses.h>
#include <sys/ioctl.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
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

// Constants
#define MAX_MAC_LIST 3
#define TL_LOG_MAX 1024
#define MSG_LEN 256
#define MAC_STRING_LEN 20
#define ENTITY_STRING_LEN 20
#define UPDATE_INTERVAL_USEC 100000	// 0.1 sec
#define MEM_NODE_ID 2		// Host ID for MECA memory node
#define NUM_TL_CHANNELS 5	// TileLink channels A-E

// Color pair indices
#define COLOR_INITIAL 1
#define COLOR_CHAN_A 2
#define COLOR_CHAN_B 3
#define COLOR_CHAN_C 4
#define COLOR_CHAN_D 5
#define COLOR_CHAN_E 6
#define COLOR_MEM 7
#define COLOR_HOST 8

// TileLink channel opcode strings
// Index by [channel][opcode], where channel 0 is unused
#if 0
static const char *chan_opcode_str[][8] = {
    {"", "", "", "", "", "", "", ""},	// Channel 0 - none is valid
    // Channel A
    {"PUTFULLDATA", "PUTPARTIALDATA", "ARITHMETICDATA", "LOGICALDATA",
     "GET", "INTENT", "ACQUIREBLOCK", "ACQUIREPERM"},
    // Channel B
    {"PUTFULLDATA", "PUTPARTIALDATA", "ARITHMETICDATA", "LOGICALDATA",
     "GET", "INTENT", "PROBEBLOCK", "PROBEPERM"},
    // Channel C
    {"ACCESSACK", "ACCESSACKDATA", "HINTACK", "NOOP",
     "PROBEACK", "PROBEACKDATA", "RELEASE", "RELEASEDATA"},
    // Channel D
    {"ACCESSACK", "ACCESSACKDATA", "HINTACK", "NOOP",
     "GRANT", "GRANTDATA", "RELEASEACK", "NOOP"},
    // Channel E
    {"GRANTACK", "", "", "", "", "", "", ""}
};
#endif
static const char *chan_opcode_str[][8] = {
    {"", "", "", "", "", "", "", ""},	// Channel 0 - none is valid
    // Channel A
    {"PutFullData", "PutPartialData", "ArithmeticData", "LogicalData",
     "Get", "Intent", "AcquireBlock", "AcquirePerm"},
    // Channel B
    {"PutFullData", "PutPartialData", "ArithmeticData", "LogicalData",
     "Get", "Intent", "ProbeBlock", "ProbePerm"},
    // Channel C
    {"AccessAck", "AccessAckData", "HintAck", "NOOP",
     "ProbeAck", "ProbeAckData", "Release", "ReleaseData"},
    // Channel D
    {"AccessAck", "AccessAckData", "HintAck", "NOOP",
     "Grant", "GrantData", "ReleaseAck", "NOOP"},
    // Channel E
    {"GrantAck", "", "", "", "", "", "", ""}
};


// Data structures
struct tl_log_entry {
    int src_id;
    int dst_id;
    int channel;
    char msg[MSG_LEN];
};

// Global state
static uint64_t src_mac[MAX_MAC_LIST] = { 0 };

static struct tl_log_entry tl_log[TL_LOG_MAX];
static int tl_log_current = 0;
static int prev_columns = 0;
static int prev_rows = 0;
static int prev_entity_num = 0;

// Forward declarations
static uint64_t get_host_mac(int id);

// ============================================================================
// Host Management Functions
// ============================================================================

/**
 * Get host ID from MAC address
 * Returns: Host ID (1-based) or -1 if not found
 */
static int get_host_id(uint64_t mac)
{
    for (int i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] == mac) {
	    return i + 1;
	}
    }
    return -1;
}

/**
 * Get MAC address from host ID
 * Returns: MAC address or 0 if invalid ID
 */
static uint64_t get_host_mac(int id)
{
    if (id > 0 && id <= MAX_MAC_LIST) {
	return src_mac[id - 1];
    }
    return 0;
}

/**
 * Add a new host to the tracking list
 */
static void add_host_id(uint64_t mac)
{
    for (int i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] == 0) {
	    src_mac[i] = mac;
	    return;
	}
    }
}

/**
 * Remove a host from the tracking list
 */
static void remove_host_id(uint64_t mac)
{
    for (int i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] == mac) {
	    src_mac[i] = 0;
	    return;
	}
    }
}

// ============================================================================
// MAC Address Conversion Functions
// ============================================================================

/**
 * Convert uint64_t MAC to string format (xx:xx:xx:xx:xx:xx)
 */
static void uint64_to_mac_string(uint64_t mac, char *mac_string)
{
    uint8_t b5 = (mac >> 40) & 0xFF;
    uint8_t b4 = (mac >> 32) & 0xFF;
    uint8_t b3 = (mac >> 24) & 0xFF;
    uint8_t b2 = (mac >> 16) & 0xFF;
    uint8_t b1 = (mac >> 8) & 0xFF;
    uint8_t b0 = (mac >> 0) & 0xFF;

    snprintf(mac_string, MAC_STRING_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
	     b0, b1, b2, b3, b4, b5);
}

/**
 * Parse MAC address string (xx:xx:xx:xx:xx:xx) to uint64_t
 * Returns: 0 on success, -1 on error
 */
static int mac_string_to_uint64(const char *mac_string, uint64_t * mac)
{
    unsigned int b0, b1, b2, b3, b4, b5;

    if (sscanf(mac_string, "%02x:%02x:%02x:%02x:%02x:%02x",
	       &b0, &b1, &b2, &b3, &b4, &b5) != 6) {
	fprintf(stderr,
		"Invalid MAC address format. Expected: xx:xx:xx:xx:xx:xx\n");
	return -1;
    }

    *mac = ((uint64_t) b5 << 40) |
	((uint64_t) b4 << 32) |
	((uint64_t) b3 << 24) |
	((uint64_t) b2 << 16) |
	((uint64_t) b1 << 8) | ((uint64_t) b0 << 0);

    return 0;
}

/**
 * Get MAC address of a network interface
 * Returns: 0 on success, -1 on error
 */
static int get_interface_mac(const char *ifname, uint64_t * mac_addr)
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

    uint8_t *mac = (uint8_t *) ifr.ifr_hwaddr.sa_data;
    *mac_addr = ((uint64_t) mac[0] << 40) |
	((uint64_t) mac[1] << 32) |
	((uint64_t) mac[2] << 24) |
	((uint64_t) mac[3] << 16) |
	((uint64_t) mac[4] << 8) | ((uint64_t) mac[5] << 0);

    return 0;
}

// ============================================================================
// TileLink Log Functions
// ============================================================================

/**
 * Add an entry to the TileLink log (circular buffer)
 */
static void tl_log_add(int src_id, int dst_id, int channel,
		       const char *msg)
{
    tl_log[tl_log_current].src_id = src_id;
    tl_log[tl_log_current].dst_id = dst_id;
    tl_log[tl_log_current].channel = channel;
    memset(tl_log[tl_log_current].msg, 0, MSG_LEN);
    strncpy(tl_log[tl_log_current].msg, msg, MSG_LEN - 1);

    tl_log_current++;
    tl_log_current %= TL_LOG_MAX;
}

/**
 * Get log entry as formatted string
 * Returns: 0 on success, -1 if entry is invalid/empty
 */
static int get_tl_log_string(int tl_log_id, char *buf)
{
    if (tl_log_id >= TL_LOG_MAX) {
	snprintf(buf, MSG_LEN, "tl_log_id %d > TL_LOG_MAX %d", tl_log_id,
		 TL_LOG_MAX);
	return -1;
    }

    int src_id = tl_log[tl_log_id].src_id;
    int dst_id = tl_log[tl_log_id].dst_id;

    // Validate source and destination IDs
    if (src_id <= 0 || src_id > MAX_MAC_LIST ||
	dst_id <= 0 || dst_id > MAX_MAC_LIST ||
	get_host_mac(src_id) == 0 || get_host_mac(dst_id) == 0 ||
	src_id == dst_id) {
	snprintf(buf, MSG_LEN, "Empty src %d dst %d", src_id, dst_id);
	return -1;
    }

    snprintf(buf, MSG_LEN, "%s", tl_log[tl_log_id].msg);
    return 0;
}

// ============================================================================
// Packet Processing
// ============================================================================

/**
 * Process TileLink message and add to log
 */
static void process_tilelink_message(const struct tl_msg_header_chan_AD
				     *tl_msg_header,
				     const struct ox_packet_struct *ox_p,
				     int src_host_id, int dst_host_id, int flit_pos)
{
    char msg[MSG_LEN];
    int channel = tl_msg_header->chan;
    int opcode = tl_msg_header->opcode;
    int data_size = 1 << tl_msg_header->size;
    int include_data = 0;

    switch (channel) {
    case CHANNEL_A:
	if (opcode == A_PUTFULLDATA_OPCODE
	    || opcode == A_PUTPARTIALDATA_OPCODE
	    || opcode == A_ARITHMETICDATA_OPCODE
	    || opcode == A_LOGICALDATA_OPCODE)
	    include_data = 1;
    case CHANNEL_B:
	if (opcode == B_PUTFULLDATA_OPCODE
	    || opcode == B_PUTPARTIALDATA_OPCODE
	    || opcode == B_ARITHMETICDATA_OPCODE
	    || opcode == B_LOGICALDATA_OPCODE)
	    include_data = 1;
    case CHANNEL_C:
	if (opcode == C_ACCESSACKDATA_OPCODE
	    || opcode == C_PROBEACKDATA_OPCODE
	    || opcode == C_RELEASEDATA_OPCODE)
	    include_data = 1;
	{
	    uint64_t addr = be64toh(ox_p->flits[flit_pos+1]);
	    if (include_data == 1) {
		snprintf(msg, MSG_LEN, "%s A:0x%lx S:%d D:0x%lx",
			 chan_opcode_str[channel][opcode], addr, data_size,
			 ox_p->flits[flit_pos+2]);
	    } else {
		snprintf(msg, MSG_LEN, "%s A:0x%lx S:%d",
			 chan_opcode_str[channel][opcode], addr,
			 data_size);
	    }
	    tl_log_add(src_host_id, dst_host_id, channel, msg);
	    break;
	}
    case CHANNEL_D:
	if (opcode == D_ACCESSACKDATA_OPCODE
	    || opcode == D_GRANTDATA_OPCODE)
	    include_data = 1;
	if (include_data == 1) {
	    snprintf(msg, MSG_LEN, "%s S:%d D:0x%lx",
		     chan_opcode_str[channel][opcode], data_size,
		     ox_p->flits[flit_pos+1]);
	} else {
	    snprintf(msg, MSG_LEN, "%s S:%d",
		     chan_opcode_str[channel][opcode], data_size);
	}
	tl_log_add(src_host_id, dst_host_id, channel, msg);
	break;
    case CHANNEL_E:
	snprintf(msg, MSG_LEN, "%s", chan_opcode_str[channel][opcode]);
	tl_log_add(src_host_id, dst_host_id, channel, msg);
	break;
    default:
	break;
    }
}

/**
 * Packet callback for libpcap
 */
static void packet_callback(u_char * user,
			    const struct pcap_pkthdr *pkthdr,
			    const u_char * packet)
{
    char buf[2048];
    struct ox_packet_struct ox_p;
    struct tl_msg_header_chan_AD tl_msg_header;

    memcpy(buf, packet, pkthdr->len);

    // Convert packet to Omnixtend structure
    packet_to_ox_struct(buf, pkthdr->len, &ox_p);
    if (ox_p.eth_hdr.eth_type != OX_ETHERTYPE)
	return;

    // Handle connection management
    if (ox_p.tloe_hdr.msg_type == CLOSE_CONN) {
	if (get_host_id(ox_p.eth_hdr.src_mac_addr) != MEM_NODE_ID) {
	    remove_host_id(ox_p.eth_hdr.src_mac_addr);
	}
	return;
    }

    if (ox_p.tloe_hdr.msg_type == OPEN_CONN) {
	if (get_host_id(ox_p.eth_hdr.src_mac_addr) == -1) {
	    add_host_id(ox_p.eth_hdr.src_mac_addr);
	}
	return;
    }
    // Get host IDs
    int src_host_id = get_host_id(ox_p.eth_hdr.src_mac_addr);
    if (src_host_id < 0)
	return;

    int dst_host_id = get_host_id(ox_p.eth_hdr.dst_mac_addr);
    if (dst_host_id < 0)
	return;

    // Process TileLink messages
    uint64_t mask = ox_p.tl_msg_mask;
    if (mask) {
	for (int i = 0; i < (sizeof(uint64_t) * 8); i++) {
	    if ((mask & 1) == 1) {
		uint64_t be64_temp = be64toh(ox_p.flits[i]);
		memcpy(&tl_msg_header, &be64_temp, sizeof(uint64_t));
		process_tilelink_message(&tl_msg_header, &ox_p,
					 src_host_id, dst_host_id, i);
	    }
	    mask = (mask >> 1);
	    if (mask == 0)
		break;
	}
    }
}

// ============================================================================
// Display Functions
// ============================================================================

/**
 * Count number of active entities (hosts)
 */
static int count_active_entities(void)
{
    int count = 0;
    for (int i = 0; i < MAX_MAC_LIST; i++) {
	if (src_mac[i] != 0)
	    count++;
    }
    return count;
}

/**
 * Draw the border frame
 */
static void draw_frame_border(int columns, int rows)
{
    int x = 0, y = 0;
    int w = columns - 1;
    int h = rows - 1;

    // Corners
    mvaddch(y, x, ACS_ULCORNER);
    mvaddch(y, x + w, ACS_URCORNER);
    mvaddch(y + h, x, ACS_LLCORNER);
    mvaddch(y + h, x + w, ACS_LRCORNER);

    // Horizontal lines
    mvhline(y, x + 1, ACS_HLINE, w - 1);
    mvhline(y + h, x + 1, ACS_HLINE, w - 1);

    // Vertical lines
    mvvline(y + 1, x, ACS_VLINE, h - 1);
    mvvline(y + 1, x + w, ACS_VLINE, h - 1);

    // Header separator
    mvaddch(y + 2, x, ACS_LTEE);
    mvaddch(y + 2, x + w, ACS_RTEE);
    mvhline(y + 2, x + 1, ACS_HLINE, w - 1);

    // Footer separator
    mvaddch(y + h - 2, x, ACS_LTEE);
    mvaddch(y + h - 2, x + w, ACS_RTEE);
    mvhline(y + h - 2, x + 1, ACS_HLINE, w - 1);
}

/**
 * Draw footer with channel legend
 */
static void draw_footer(int columns, int rows)
{
    int y = rows - 2;
    mvprintw(y, 2, "MECA Memory Protocol Viewer\tChannel: ");

    for (int i = 1; i <= NUM_TL_CHANNELS; i++) {
	attron(COLOR_PAIR(COLOR_CHAN_A + i - 1));
	printw("%c", 'A' + i - 1);
	attroff(COLOR_PAIR(COLOR_CHAN_A + i - 1));
	printw("  ");
    }
    printw("\t\tPress 'q' to exit");
}

/**
 * Draw entity (host) dividers and labels
 */
static void draw_entity_dividers(int columns, int rows, int entity_num,
				 const int *entity_border)
{
    int x = 0, y = 0;
    int h = rows - 1;

    // Draw vertical dividers between entities
    for (int i = 1; i < entity_num; i++) {
	mvaddch(y + h - 2, entity_border[i], ACS_BTEE);
	mvaddch(y + 2, entity_border[i], ACS_PLUS);
	mvvline(y + 3, entity_border[i], ACS_VLINE, h - 5);
	mvaddch(y, entity_border[i], ACS_TTEE);
	mvvline(y + 1, entity_border[i], ACS_VLINE, 1);
    }

    // Draw entity labels
    int entity_idx = 0;
    int host_num = 0;
    for (int i = 1; i <= MAX_MAC_LIST; i++) {
	uint64_t mac = get_host_mac(i);
	if (mac != 0) {
	    char mac_string[MAC_STRING_LEN];
	    char entity_string[ENTITY_STRING_LEN];
	    uint64_to_mac_string(mac, mac_string);

	    int center_x =
		(entity_border[entity_idx] +
		 entity_border[entity_idx + 1]) / 2;

	    if (i == MEM_NODE_ID) {
		snprintf(entity_string, ENTITY_STRING_LEN, "MECA MEM");
		attron(COLOR_PAIR(COLOR_MEM));
		mvprintw(y + 1, center_x - strlen(entity_string) / 2 - 8,
			 "%s", entity_string);
		attroff(COLOR_PAIR(COLOR_MEM));
	    } else {
		snprintf(entity_string, ENTITY_STRING_LEN, "Host %d",
			 host_num++);
		attron(COLOR_PAIR(COLOR_HOST));
		mvprintw(y + 1, center_x - strlen(entity_string) / 2 - 8,
			 "%s", entity_string);
		attroff(COLOR_PAIR(COLOR_HOST));
	    }
	    printw("(%s)", mac_string);
	    entity_idx++;
	}
    }
}

/**
 * Draw TileLink message log entries
 */
static void draw_tl_log_entries(int columns, int rows, int entity_num,
				const int *entity_border)
{
    int h = rows - 1;
    int w = columns - 1;
    int max_msg = (h / 2) - 3;
    if (max_msg < 0)
	max_msg = 0;

    int msg_num = 0;
    for (int i = max_msg; i > 0 && msg_num < max_msg; i--) {
	int tl_log_id = (tl_log_current - i) % TL_LOG_MAX;
	char msg[MSG_LEN];

	if ( tl_log_id < 0 ) continue;

	if (get_tl_log_string(tl_log_id, msg) == 0) {
	    int src_id = tl_log[tl_log_id].src_id;
	    int dst_id = tl_log[tl_log_id].dst_id;
	    int channel = tl_log[tl_log_id].channel;
	    int row = 4 + (msg_num * 2);

	    // Clear the row
	    for (int j = 0; j < entity_num; j++) {
		move(row, entity_border[j] + 1);
		for (int k = 0; k < (w / entity_num - 1); k++)
		    addch(' ');
	    }

	    // Draw log ID
	    mvprintw(row, 1, "%04d", tl_log_id);

	    // Calculate available width for message
	    int entity_border_id = src_id;
	    int entity_width;
	    if (src_id > dst_id) {
		entity_width = entity_border[entity_border_id] -
			       entity_border[entity_border_id - 1] - 6; // "<-- " + margin
	    } else {
		entity_width = entity_border[entity_border_id] -
			       entity_border[entity_border_id - 1] - 6; // " -->" + margin
	    }

	    // Truncate message if too long
	    char display_msg[MSG_LEN];
	    int msg_len = strlen(msg);
	    if (msg_len > entity_width && entity_width > 3) {
		strncpy(display_msg, msg, entity_width - 3);
		display_msg[entity_width - 3] = '\0';
		strcat(display_msg, "...");
	    } else if (entity_width <= 3) {
		display_msg[0] = '\0';  // Too narrow to display anything
	    } else {
		strncpy(display_msg, msg, MSG_LEN - 1);
		display_msg[MSG_LEN - 1] = '\0';
	    }

	    // Draw message with direction arrow
	    if (src_id > dst_id) {
		mvprintw(row, entity_border[entity_border_id - 1] - 1,
			 "<-- ");
		attron(COLOR_PAIR(channel + 1));
		printw("%s", display_msg);
		attroff(COLOR_PAIR(channel + 1));
	    } else {
		int display_msg_len = strlen(display_msg);
		attron(COLOR_PAIR(channel + 1));
		mvprintw(row,
			 entity_border[entity_border_id] - 2 - display_msg_len,
			 "%s", display_msg);
		attroff(COLOR_PAIR(channel + 1));
		printw(" -->");
	    }

	    msg_num++;
	}
    }
}

/**
 * Main draw function combining all display elements
 */
static void draw_border(int columns, int rows)
{
    int entity_num = count_active_entities();

    // Clear screen if entity count changed
    if (entity_num != prev_entity_num) {
	erase();
	refresh();
	prev_entity_num = entity_num;
    }

    if (entity_num == 0)
	return;

    // Calculate entity borders
    int entity_border[MAX_MAC_LIST + 1];
    int w = columns - 1;
    for (int i = 0; i <= entity_num; i++) {
	entity_border[i] = i * (w / entity_num);
    }

    draw_frame_border(columns, rows);
    draw_footer(columns, rows);
    draw_entity_dividers(columns, rows, entity_num, entity_border);
    draw_tl_log_entries(columns, rows, entity_num, entity_border);
}

/**
 * Main screen drawing function
 */
static void draw_screen(void)
{
    struct winsize ts;

    // Get terminal dimensions
    ioctl(0, TIOCGWINSZ, &ts);
    int columns = ts.ws_col;
    int rows = ts.ws_row;

    // Clear screen if dimensions changed
    if (prev_columns != columns || prev_rows != rows) {
	erase();
	refresh();
	prev_columns = columns;
	prev_rows = rows;
    }

    draw_border(columns, rows);
    refresh();
}

// ============================================================================
// Thread and Signal Handlers
// ============================================================================

/**
 * Status update thread - refreshes display and handles input
 */
static void *status_update_thread(void *data)
{
    int interval_usec = *((int *) data);
    char ch;
    int flags;
    struct termios t;

    // Set up non-blocking input
    flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
    tcgetattr(STDIN_FILENO, &t);
    t.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t);

    while (1) {
	draw_screen();
	usleep(interval_usec);

	// Check for quit command
	ssize_t bytes = read(STDIN_FILENO, &ch, 1);
	if (bytes > 0 && ch == 'q') {
	    endwin();
	    exit(0);
	}
    }

    return NULL;
}

/**
 * Signal handler for Ctrl+C
 */
static void handle_sigint(int signum)
{
    (void) signum;		// Unused parameter
    endwin();
    exit(0);
}

// ============================================================================
// Main Function
// ============================================================================

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pthread_t pid;
    int interval_usec = UPDATE_INTERVAL_USEC;
    uint64_t mem_mac = 0;
    char *dev;

    // Parse command line arguments
    if (argc < 4) {
	printf("Usage: %s [interface] --mem_mac xx:xx:xx:xx:xx:xx\n",
	       argv[0]);
	return 0;
    }

    dev = argv[1];

    // Parse --mem_mac argument
    for (int i = 2; i < argc; i++) {
	if (strcmp(argv[i], "--mem_mac") == 0) {
	    if (i + 1 < argc) {
		if (mac_string_to_uint64(argv[i + 1], &mem_mac) < 0) {
		    fprintf(stderr,
			    "Failed to parse memory MAC address\n");
		    return 1;
		}
		i++;
	    } else {
		fprintf(stderr,
			"--mem_mac requires a MAC address argument\n");
		return 1;
	    }
	}
    }

    // Register signal handler
    signal(SIGINT, handle_sigint);

    // Register memory MAC address
    if (mem_mac != 0) {
	src_mac[1] = mem_mac;
	int host_id = get_host_id(mem_mac);
	char mac_string[MAC_STRING_LEN];
	uint64_to_mac_string(mem_mac, mac_string);
	printf("Memory MAC: %s, Host ID: %d\n", mac_string, host_id);
    }
    // Initialize log buffer
    memset(tl_log, 0, sizeof(struct tl_log_entry) * TL_LOG_MAX);

    // Initialize ncurses
    setlocale(LC_ALL, "C-UTF-8");
    initscr();
    start_color();

    // Initialize color pairs
    init_pair(COLOR_INITIAL, COLOR_WHITE, COLOR_BLACK);
    init_pair(COLOR_CHAN_A, COLOR_WHITE, COLOR_RED);
    init_pair(COLOR_CHAN_B, COLOR_WHITE, COLOR_BLUE);
    init_pair(COLOR_CHAN_C, COLOR_BLACK, COLOR_WHITE);
    init_pair(COLOR_CHAN_D, COLOR_BLACK, COLOR_GREEN);
    init_pair(COLOR_CHAN_E, COLOR_BLACK, COLOR_MAGENTA);
    init_pair(COLOR_MEM, COLOR_RED, COLOR_BLACK);
    init_pair(COLOR_HOST, COLOR_GREEN, COLOR_BLACK);

    // Start display update thread
    if (pthread_create
	(&pid, NULL, status_update_thread, (void *) &interval_usec)) {
	perror("Thread create error");
	endwin();
	return 1;
    }
    // Open packet capture
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
	endwin();
	return 1;
    }
    // Start capturing packets
    pcap_loop(handle, 0, packet_callback, NULL);

    // Cleanup
    pcap_close(handle);
    endwin();
    return 0;
}
