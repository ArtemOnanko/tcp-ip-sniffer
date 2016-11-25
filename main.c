/*  Compile       gcc -Wall -o main main.c -lpcap  */
/*  Run           sudo ./main		           */

#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>

#define SIZE_ETHERNET 14    //ethernet headers are always exactly 14 bytes

// ip header
struct sniff_ip 
{
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f) // IP Length
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)   // IP version

// Declaring log files
FILE* IP_log_sniff;         
FILE* IP_log_stat;

// defining node structure
typedef struct node 
{
    bool is_word;
    struct node* children[11];
    unsigned long int num_of_packets;
}
node;
    
// function for creating empty node
node* createNewNode(void) 
{
    node* newNode = malloc(sizeof (node));
    newNode -> num_of_packets = 0;
    newNode -> is_word = false;
    for (int i = 0; i < 11; i++) 
    {
        newNode -> children[i] = NULL;
    }
    return newNode;
}

// function for symbol "insertion" to the trie
node* insertSymbol(node* current, int i) 
{
    if (current -> children[i] == NULL) 
    {
        node* newNode = createNewNode();
        current -> children[i] = newNode;
        current = newNode;
    } 
    else 
    {
        current = current -> children[i];
    }
    return current;
}
// defining root node
node* root;

// free node
void freeNode(node* node) 
{
    for (int i = 0; i < 11; i++) 
    {
        // if node's children point to somewhere
        if (node -> children[i] != NULL) 
        {
            // recursevely calling next level node and checking it's children
            freeNode(node -> children[i]);
        }
    }
    // if node's children point to nowhere - clearing this node
    free(node);
}

// Unloads structure from memory.  Returns true if successful else false.
bool unload(void) 
{
    // should free all malloced nodes plus root node
    freeNode(root);
    return true;
}

// load function prototype
bool load(char* dev);

// IP search function prototype
unsigned long int search(const char* word); 

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 1;           //packet counter
    
    // declare pointers to packet headers 
    const struct sniff_ip *ip;      // The IP header
    unsigned int size_ip;
    printf("\nPacket number %d:\n", count);
    count++;
			
    // define/compute ip header offset 
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) 
    {
	printf("   * Invalid IP header length: %u bytes\n", size_ip);
	return;
    }

    // print source IP address 
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    
    // print source IP address to log file
    fprintf(IP_log_sniff,"%s\n", inet_ntoa(ip->ip_src));
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev;
    pcap_t *handle;
    bpf_u_int32 mask;		// The netmask of our sniffing device
    bpf_u_int32 net;		// The IP of our sniffing device 
    struct bpf_program fp;	// The compiled filter expression 
    char filter_exp[] = "tcp";  // The filter expression
        
    // setting the default device
    dev = "wlp2s0";
    
    // Opens the log file for appending       
    IP_log_sniff = fopen(dev, "a");
    // checking if log file opens
    if (IP_log_sniff == NULL) 
    {
        fprintf(stderr, "Could not open log file");
        exit(EXIT_FAILURE);
    } 
            
    // get network number and mask associated with capture device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
    {
	fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
	net = 0;
	mask = 0;
    }       
            
    // openening the device for sniffing in non-promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	exit(EXIT_FAILURE);
    }
            
    // in case link-layer header type is not supported
    if (pcap_datalink(handle) != DLT_EN10MB) 
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
        exit(EXIT_FAILURE);
    }
            
    //  sniffing all incoming network traffic
    pcap_setdirection(handle,PCAP_D_IN);
    
    // compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
    {
	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	exit(EXIT_FAILURE);
    }

    // apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) 
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
                          
    // now we can set our callback function (500 packets)
    pcap_loop(handle, 500, got_packet, NULL);
    
    //stop loop realization
        
    // cleanup
    fclose(IP_log_sniff);
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\nCapture complete.\n");   
    
    // loading structure trie from IP_log_sniff
    bool loaded = load(dev);
    
    // abort if structure not loaded
    if (!loaded)
    {
        fprintf(stderr, "Could not load structure from %s file.\n", dev);
        exit(EXIT_FAILURE);
    }
    
    // search for curren IP
    unsigned long int packets_from_ip = search("173.194.44.71");
    printf("From 173.194.44.71 got %lu packets\n", packets_from_ip);
       
    // unload structure trie
    bool unloaded = unload();
    
    // abort if dictionary not unloaded
    if (!unloaded)
    {
        fprintf(stderr, "Could not unload %s.\n", dev);
        exit(EXIT_FAILURE);
    }
    return(0);
}

// loading IP words from IP_log_sniff file to a trie struct
bool load(char* dev) 
{
    root = createNewNode();
    // defining current node pointing to root
    node* current = root;
    // opening log file for reading
    FILE* IP_log_sniff = fopen(dev, "r");
    // checking if file opens
    if (IP_log_sniff == NULL) 
    {
        return false;
    } 
    else 
    {
        int index = 0;      // index for children[]
        char word[15+2];    // IP word + eol +eof 192.168.001.001 = 15 
        while (true) 
        {
            //getting strings from IP_log_sniff one by one
            fgets (word, 15+2, IP_log_sniff); 
                
                for (int i = 0; word[i] != 10; i++) // till the eol
                {
                    if (word[i] == 46)    // dot
                        index = 10;
                    else
                        index = word[i] - 48; //asci code of 0 = 48
                    current = insertSymbol(current, index);
                }
            
            if (feof(IP_log_sniff))     // till the eof
            {
                break;
            }
            current -> is_word = true;
            if(current -> is_word == true)
                current -> num_of_packets = (current -> num_of_packets) + 1;
            current = root;
        }
        fclose(IP_log_sniff);
        return true;
    }
}

unsigned long int search(const char* word) 
{
     // defining current node pointing to root
    node* current = root;
    int index = 0;
    int c = 0;
    for (int i = 0; i < 15+2; i++) // 15 - length of ip word
    {
        c = word[i];
        if (c >= 48 && c <= 57) // numbers
            index = c - 48; //asci code of 0 = 48
        else if (c == 46) // dot
            index = 10;
        else if (current -> is_word == true) // empty
            return current -> num_of_packets;
        else
        {
            printf("No such IP in the list\n");
            return 0;
        }
        if (current -> children[index] == NULL)
        {
            printf("No such IP in the list\n");
            return 0;
        }
        else
            current = current -> children[index];
    }
    printf("No such IP in the list\n");
    return 0;
}
