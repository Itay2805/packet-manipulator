#include <sys/socket.h>
#include <net/ethernet.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <endian.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <malloc.h>

///////////////////////////////////////////////
// libpcap loaded functions
///////////////////////////////////////////////

typedef struct pcap_if {
    struct pcap_if* next;
    char* name;
    char* description;
    struct pcap_addr* addresses;
    int32_t flags;
} pcap_if_t;

struct pcap_addr {
    struct pcap_addr* next;
    struct sockaddr addr;
    struct sockaddr netmask;
    struct sockaddr broadaddr;
    struct sockaddr dstaddr;
};

struct pcap_pkthdr {
    struct timeval ts;
    int32_t caplen;
    int32_t len;
};

struct pcap_stat {
    int32_t ps_recv;
    int32_t ps_drop;
    int32_t ps_ifdrop;
};

typedef void pcap_t;
typedef void pcap_dumper_t;

static const char*  (*pcap_lib_version)(void);
static int          (*pcap_findalldevs)(pcap_if_t **alldevsp, char *errbuf);
static void         (*pcap_freealldevs)(pcap_if_t *alldevsp);
static pcap_t*      (*pcap_open_live)(const char* device, int snaplen, int promisc, int to_ms, char* errbuf);
void                (*pcap_close)(pcap_t*p);
int                 (*pcap_datalink)(pcap_t *p);
char*               (*pcap_next)(pcap_t *p, struct pcap_pkthdr *h);
int                 (*pcap_setnonblock)(pcap_t *p, int nonblock, char *errbuf);
int                 (*pcap_getnonblock)(pcap_t *p, char *errbuf);
char*               (*pcap_lookupdev)(char *errbuf);
char*               (*pcap_strerror)(int errno);
char*               (*pcap_geterr)(pcap_t *p);
int                 (*pcap_stats)(pcap_t *p, struct pcap_stat *ps);

pcap_dumper_t*      (*pcap_dump_open)(pcap_t *p, const char *fname);
void                (*pcap_dump)(pcap_dumper_t * dumper, const struct pcap_pkthdr *h, const u_char *sp);
int                 (*pcap_dump_flush)(pcap_dumper_t *p);
long                (*pcap_dump_ftell)(pcap_dumper_t *);
void                (*pcap_dump_close)(pcap_dumper_t *p);

///////////////////////////////////////////////
// stream handling
///////////////////////////////////////////////

void write_bool(bool b) {
    fwrite(&b, 1, 1, stdout);
    fflush(stdout);
}

int32_t read_int() {
    int32_t num = 0;
    fread(&num, 4, 1, stdin);
    return num;
}

int64_t read_long() {
    int64_t num = 0;
    fread(&num, 8, 1, stdin);
    return num;
}

void write_int(int32_t num) {
    fwrite(&num, 4, 1, stdout);
    fflush(stdout);
}

void write_long(int64_t num) {
    fwrite(&num, 8, 1, stdout);
    fflush(stdout);
}

void write_string(const char* str) {
    if(str == NULL) {
        write_int(0);
    }else {
        write_int(strlen(str));
        fwrite(str, strlen(str), 1, stdout);
    }
    fflush(stdout);
}

char* read_string() {
    int len = read_int();
    char* buf = malloc((size_t) len + 1);
    fread(buf, 1, (size_t) len, stdin);
    buf[len] = 0;
    return buf;
}

///////////////////////////////////////////////
// the handler implementations
///////////////////////////////////////////////

void comm_pcap_lib_version() {
    write_string(pcap_lib_version());
}

void comm_pcap_findalldevs() {
    pcap_if_t* pifs = NULL;
    char buffer[256] = {0};

    // try to find all interfaces
    if(pcap_findalldevs(&pifs, buffer) != 0) {
        fprintf(stderr, "errbuf -> %s\n", buffer);
        fflush(stderr);

        // go an error
        write_bool(false);
        write_string(buffer);

    }else {

        // everything is good
        write_bool(true);

        // find how many devices there are
        int devs_count = 0;
        if(pifs != NULL) {
            pcap_if_t* cur = pifs;
            do {
                devs_count++;
            } while((cur = cur->next) != NULL);
        }

        // iterate and write out the devices
        write_int(devs_count);
        pcap_if_t* cur = pifs;
        while(cur != NULL) {
            // write the name and description
            write_string(cur->name);
            write_string(cur->description);

            // check how many addresses are there
            int addr_count = 0;
            if(cur->addresses != NULL) {
                struct pcap_addr* addr = cur->addresses;
                do {
                    addr_count++;
                } while((addr = addr->next) != NULL);
            }

            // write the addresses
            write_int(addr_count);
            struct pcap_addr* addr = cur->addresses;
            while(addr != NULL) {
                fwrite(addr, sizeof(struct sockaddr) * 4, 1, stdout);
                fflush(stdout);

                addr = addr->next;
            }

            // write the flags
            write_int(cur->flags);

            cur = cur->next;
        }

    }

    // free them
    pcap_freealldevs(pifs);
}

void comm_pcap_open_live() {
    char buffer[256] = {0};

    char* device = read_string();
    int spanlen = read_int();
    int promisc = read_int();
    int to_ms = read_int();

    void* pcap = pcap_open_live(device, spanlen, promisc, to_ms, buffer);
    if(pcap == NULL) {

        fprintf(stderr, "errbuf -> %s\n", buffer);
        fflush(stderr);

        write_bool(false);
        write_string(buffer);

    }else {

        write_bool(true);
        write_long((uint64_t)pcap);

    }

    free(device);
}

void comm_pcap_close() {
    void* handle = (void*)read_long();
    pcap_close(handle);
}

void comm_pcap_datalink() {
    void* handle = (void*)read_long();
    write_int(pcap_datalink(handle));
}

void comm_pcap_next() {
    void* handle = (void*)read_long();

    struct pcap_pkthdr header;
    void* data = pcap_next(handle, &header);

    if(data == NULL) {
        write_bool(false);
    }else {
        write_bool(true);

        write_long(header.ts.tv_sec);
        write_long(header.ts.tv_usec);
        write_int(header.caplen);
        write_int(header.len);
        fwrite(data, 1, (size_t) header.caplen, stdout);
        fflush(stdout);
    }
}

void comm_pcap_setnonblock() {
    char errbuf[256] = {0};

    void* handle = (void*)read_long();
    int nonblock = read_int();

    if(pcap_setnonblock(handle, nonblock, errbuf) != 0) {

        write_bool(false);
        write_string(errbuf);

    }else {

        write_bool(true);

    }
}

void comm_pcap_getnonblock() {
    char errbuf[256] = {0};

    void* handle = (void*)read_long();
    int nonblock = pcap_getnonblock(handle, errbuf);

    if(nonblock < 0) {

        write_bool(false);
        write_string(errbuf);

    }else {

        write_bool(true);
        write_int(nonblock);

    }
}

void comm_pcap_lookupdev() {
    char errbuf[256] = {0};

    char* device = pcap_lookupdev(errbuf);

    if(device == NULL) {

        write_bool(false);
        write_string(errbuf);

    }else {

        write_bool(true);
        write_string(device);

    }
}

void comm_pcap_strerror() {
    int error = read_int();
    write_string(pcap_strerror(error));
}

void comm_pcap_geterr() {
    void* handle = (void*)read_long();
    write_string(pcap_geterr(handle));
}

void comm_pcap_stats() {
    void* handle = (void*)read_long();

    struct pcap_stat stats = {0};
    pcap_stats(handle, &stats);

    write_int(stats.ps_recv);
    write_int(stats.ps_drop);
    write_int(stats.ps_ifdrop);
}

void comm_pcap_dump_open() {
    void* handle = (void*)read_long();
    char* str = read_string();
    void* res = pcap_dump_open(handle, str);
    write_long((int64_t) res);
    free(str);
}

void comm_pcap_dump() {
    void* handle = (void*)read_long();
    struct pcap_pkthdr header = {0};
    header.ts.tv_sec = (__kernel_time_t) read_long();
    header.ts.tv_usec = (__kernel_time_t) read_long();
    header.caplen = read_int();
    header.len = read_int();
    char* buffer = malloc((size_t) header.len);
    fread(buffer, 1, (size_t) header.len, stdin);
    pcap_dump(handle, &header, (const u_char *) buffer);
    free(buffer);
}

void comm_pcap_dump_flush() {
    void* handle = (void*)read_long();
    int rc = pcap_dump_flush(handle);
    if(rc != 0) {

        write_bool(false);
        write_string(pcap_strerror(rc));

    }else {

        write_bool(true);

    }
}

void comm_pcap_dump_ftell() {
    void* handle = (void*)read_long();
    pcap_dump_close(handle);
}

void comm_pcap_dump_close() {
    void* handle = (void*)read_long();
    pcap_dump_close(handle);
}

///////////////////////////////////////////////
// Server main
///////////////////////////////////////////////

// function constatns
#define PCAP_LIB_VERSION    1
#define PCAP_FINDALLDEVS    2
#define PCAP_OPEN_LIVE      3
#define PCAP_CLOSE          4
#define PCAP_DATALINK       5
#define PCAP_NEXT           6
#define PCAP_SETNONBLOCK    7
#define PCAP_GETNONBLOCK    8
#define PCAP_LOOKUPDEV      9
#define PCAP_STRERROR       10
#define PCAP_GETERR         11
#define PCAP_STATS          12
#define PCAP_DUMP_OPEN      13
#define PCAP_DUMP           14
#define PCAP_DUMP_FLUSH     15
#define PCAP_DUMP_FTELL     16
#define PCAP_DUMP_CLOSE     17

// handlers per function
typedef void (*command_handler_t)();
command_handler_t handlers[] = {
        [PCAP_LIB_VERSION] = comm_pcap_lib_version,
        [PCAP_FINDALLDEVS] = comm_pcap_findalldevs,
        [PCAP_OPEN_LIVE] = comm_pcap_open_live,
        [PCAP_CLOSE] = comm_pcap_close,
        [PCAP_DATALINK] = comm_pcap_datalink,
        [PCAP_NEXT] = comm_pcap_next,
        [PCAP_SETNONBLOCK] = comm_pcap_setnonblock,
        [PCAP_GETNONBLOCK] = comm_pcap_getnonblock,
        [PCAP_LOOKUPDEV] = comm_pcap_lookupdev,
        [PCAP_STRERROR] = comm_pcap_strerror,
        [PCAP_GETERR] = comm_pcap_geterr,
        [PCAP_STATS] = comm_pcap_stats,
        [PCAP_DUMP_OPEN] = comm_pcap_dump_open,
        [PCAP_DUMP] = comm_pcap_dump,
        [PCAP_DUMP_FLUSH] = comm_pcap_dump_flush,
        [PCAP_DUMP_FTELL] = comm_pcap_dump_ftell,
        [PCAP_DUMP_CLOSE] = comm_pcap_dump_close,
};

#define LOAD_FUNC(name) \
    do { \
        name = dlsym(handle, #name); \
        if(name == NULL) { \
            fprintf(stderr, "Failed to get function %s - %s\n", #name, dlerror()); \
            return -1; \
        } \
    } while(0)

/*
 * This is called
 */
int main(int argc, char* argv[]) {
    fprintf(stderr, "pcap proxy process main\n");

    // attempt to open libpcap
    void* handle = dlopen("libpcap.so", RTLD_LAZY);
    if(handle == NULL) {
        fprintf(stderr, "Failed to open libpcap.so - %s\n", dlerror());
        fflush(stderr);
        return -1;
    }

    // load all the functions
    LOAD_FUNC(pcap_lib_version);
    LOAD_FUNC(pcap_findalldevs);
    LOAD_FUNC(pcap_freealldevs);
    LOAD_FUNC(pcap_open_live);
    LOAD_FUNC(pcap_close);
    LOAD_FUNC(pcap_datalink);
    LOAD_FUNC(pcap_next);
    LOAD_FUNC(pcap_setnonblock);
    LOAD_FUNC(pcap_getnonblock);
    LOAD_FUNC(pcap_lookupdev);
    LOAD_FUNC(pcap_strerror);
    LOAD_FUNC(pcap_geterr);
    LOAD_FUNC(pcap_stats);
    LOAD_FUNC(pcap_dump_open);
    LOAD_FUNC(pcap_dump);
    LOAD_FUNC(pcap_dump_flush);
    LOAD_FUNC(pcap_dump_ftell);
    LOAD_FUNC(pcap_dump_close);

    // handling of commands
    while(1) {
        int comm = read_int();
        if(comm >= (sizeof(handlers) / sizeof(handlers[0]))) {

            // invalid command number
            fprintf(stderr, "Invalid command `%d`\n", comm);
            fflush(stderr);

        }else {
            // run the command
            handlers[comm]();

            // flush, just in case
            fflush(stdout);
        }
    }
}
