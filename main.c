#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>

#define SHMSZ     27        // shared memory size (for menu commands)
#define SIZE_ETHERNET 14    //ethernet headers are always exactly 14 bytes
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f) // IP Length
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)   // IP version
// ip header
struct sniff_ip 
{
    u_char ip_vhl; /* version << 4 | header length >> 2 */
    u_char ip_tos; /* type of service */
    u_short ip_len; /* total length */
    u_short ip_id; /* identification */
    u_short ip_off; /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char ip_ttl; /* time to live */
    u_char ip_p; /* protocol */
    u_short ip_sum; /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

// global variables
char *dev; 
char * select_buff;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
bpf_u_int32 mask; // The netmask of our sniffing device
bpf_u_int32 net;  // The IP of our sniffing device 
struct bpf_program fp; // The compiled filter expression 
char filter_exp[] = "tcp"; // The filter expression
char buffer[16]; // Defining the buffer for IP statistics
int shmid;       // shared memory ID
key_t key;       // key for shared memory
char *shm;       // shared memory
char temp_shm[27]; // temporary value of shared memory
bool preset_indicator;

// declaring log files
FILE* IP_log_sniff;

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

// unloads structure from memory.  Returns true if successful else false.
bool unload(void) 
{
    // should free all malloced nodes plus root node
    freeNode(root);
    return true;
}

// load function prototype
bool load(char* dev);

// IP search function prototype
int show(char* word);

// whole statistics function prototype
void statistics(node* node, int depth, char buff[]);

// writing packet info to the file and to the screen
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) 
{
    static int count = 1;       // packet counter (should be static here)

    // declare pointers to packet headers 
    const struct sniff_ip *ip;  // The IP header
    unsigned int size_ip;
    printf("\nPacket number %d:\n", count);
    count++;

    // define/compute ip header offset 
    ip = (struct sniff_ip*) (packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) 
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // print source IP address 
    printf("       From: %s\n", inet_ntoa(ip->ip_src));

    // print source IP address to log file
    fprintf(IP_log_sniff, "%s\n", inet_ntoa(ip->ip_src));
}

// function for preparing the sniffing device  
bool preset(char* dev) 
{
    // get network number and mask associated with capture device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
    {
        printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
        preset_indicator = false;
        return false;
    }

    // openening the device for sniffing in non-promiscuous mode
    handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
    if (handle == NULL) 
    {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        preset_indicator = false;
        return false;
    }

    // in case link-layer header type is not supported
    if (pcap_datalink(handle) != DLT_EN10MB) 
    {
        printf("Device %s doesn't provide Ethernet headers - not supported\n", dev);
        preset_indicator = false;
        return false;
    }

    //  sniffing all INCOMING network traffic
    pcap_setdirection(handle, PCAP_D_IN);

    // compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
    {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        preset_indicator = false;
        return false;
    }

    // apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) 
    {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        preset_indicator = false;
        return false; 
    }
    printf("Device %s is ready for sniffing\n", dev);
    preset_indicator = true;
    return true;
}

void text(void) 
{
    printf("Print start for sniffing\n");
    printf("Print stop to stop sniffing\n");
    printf("Print show [ip] to show number of packets gets from [ip] on current interface\n");
    printf("Print select [iface] to select interface for sniffing\n");
    printf("Print stat [iface] to show collected statistics on chosen interface\n");
    printf("Print quit to exit\n");
    printf("Print help for help\n");
}

void cleanup(void)              // close IP_log_sniff
{
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\nCapture complete.\n"); 
}

int main() 
{   
    // forking processes: sniffing and menu
    pid_t pid = fork();

    if (pid > 0) // parent process (MENU)
    {       
        // We'll name our shared memory segment "1234".      
        key = 1234;

        // Create the segment.
        if ((shmid = shmget(key, SHMSZ, IPC_CREAT | 0666)) < 0) 
        {
            printf("Couldn't create the segment\n");
            exit(EXIT_FAILURE);
        }

        // Now we attach the segment to our data space.
        if ((shm = shmat(shmid, NULL, 0)) == (char *) - 1) 
        {
            printf("Couldn't attache the segment to our data space\n");
            exit(EXIT_FAILURE);
        }

        // Now put some things into the memory for the other process to read.
        for (int i = 0; i < 27; i++)
        {
            shm[i] = 0;
        }
        do 
        {
            fgets(shm, 27, stdin);
            shm[strcspn(shm, "\n")] = 0;    // thus we exlude \n from shm
        } 
        while (strcmp(shm, "quit") != 0);
        wait(0);                            // waiting for child process to exit
        
        // deleting shared memory segment
        shmctl(key, IPC_RMID, NULL);
        exit(EXIT_SUCCESS);
    }
    else if (pid == 0)                      // child process (SNIFFING) 
    {
        key = 1234;

        // Locate the segment.
        if ((shmid = shmget(key, SHMSZ, 0666)) < 0) 
        {
            printf("Couldn't locate the segment\n");
            exit(EXIT_FAILURE);
        }

        // Now we attach the segment to our data space.
        if ((shm = shmat(shmid, NULL, 0)) == (char *) - 1) 
        {
            printf("Couldn't attache the segment to our data space\n");
            exit(EXIT_FAILURE);
        }

        // Now read what the parent put in the memory.
        dev = pcap_lookupdev(errbuf);       // default device (causes some valgrind errors)
        text();
        
        if (preset(dev) == false)
        {
            printf("Couldn't sniff on default device! Print select [iface] for chosing new device or quit to exit\n");
            while(1)
            {
                if(strncmp(shm, "select ", 7) == 0 || strcmp(shm, "quit") == 0)
                    break;
            }  
        }
        else
        {
            // Opens the log file for appending       
            IP_log_sniff = fopen(dev, "a");
    
            // checking if the log file opens
            if (IP_log_sniff == NULL) 
            {
                printf("Couldn't open log file\n");
                exit(EXIT_FAILURE);
            }
            printf ("Start sniffing on %s device...\n", dev);
        } 
         
        // default sniffing loop
        while (strcmp(shm, "quit") != 0) 
        {   
            // case if default snoffing device fault
            if((strncmp(shm, "select ", 7) == 0 || strcmp(shm, "quit") == 0) && preset_indicator == false)
                break;
            
            pcap_dispatch(handle, 1, got_packet, NULL);
            
            // case if default snoffing device ok
            if (strcmp(shm, "stop") == 0 || strncmp(shm, "select ", 7) == 0 || strncmp(shm, "stat ", 5) == 0 || strcmp(shm, "quit") == 0 || strcmp(shm, "help") == 0 || strncmp(shm, "show ", 5) == 0)
            {
                fclose(IP_log_sniff);
                break;  
            }
        }
                        
        // menu commands processing 
        while(strcmp(shm, "quit") != 0)
        {
            // start manual sniffing
            if (strcmp(shm, "start") == 0)
            {
                printf ("Start sniffing on %s device...\n", dev);
                
                // Opens the log file for appending       
                IP_log_sniff = fopen(dev, "a");
    
                // checking if the log file opens
                if (IP_log_sniff == NULL) 
                {
                    printf("Couldn't open log file\n");
                    exit(EXIT_FAILURE);
                }
                
                while (strcmp(shm, "stop") != 0 && strncmp(shm, "select ",7) != 0 && strncmp(shm,"stat ", 5) != 0 && strcmp(shm,"quit") != 0 && strcmp(shm,"help") != 0 && strncmp(shm, "show ", 5) != 0) 
                {   
                    pcap_dispatch(handle, 1, got_packet, NULL);
                }
                fclose(IP_log_sniff);
            }
            
            // display help message
            if (strcmp(shm, "help") == 0)
            {
                text();
                while(strcmp(shm, "help") == 0)
                {
                }  
            }
            
            // statistics
            if (strncmp(shm, "stat ", 5) == 0)
            {
                char * stat_buff = strchr (shm, ' ') + 1;            
                bool loaded = load(stat_buff);
                
                // abort if structure not loaded
                if (!loaded) 
                {
                    printf("Couldn't load trie structure from %s file.\n", stat_buff);
                }
                else
                {
                    printf("From %s device we got:\n\n", stat_buff);
                    
                    // printing whole statistis
                    statistics(root, 0, buffer);
                    
                    // unload structure trie
                    bool unloaded = unload();
    
                    // abort if trie not unloaded
                    if (!unloaded) 
                    {
                        printf("Could not unload trie %s.\n", stat_buff);
                        exit(EXIT_FAILURE);
                    }
                }
                while(1) 
                {
                    strncpy(temp_shm, shm, 27);
                    if (strncmp(shm, "show ", 5) == 0 || strncmp(shm, "select ", 7) == 0 || strcmp(shm, "help") == 0 || strcmp(shm, "start") == 0 || strcmp(shm, "quit") == 0 || (strcmp(shm, temp_shm) != 0 && strncmp(shm, "stat ", 5) == 0))
                    {
                        break;
                    }
                }  
            }
            
            // show IP
            if (strncmp(shm, "show ", 5) == 0)
            {
                // loading trie
                bool loaded = load(dev);
                
                // abort if structure not loaded
                if (!loaded) 
                {
                    printf("Couldn't load trie structure from %s file.\n", dev);
                }
                else
                {
                    char* show_buff = strchr (shm, ' ') + 1; 
                    printf("From %s got %d packets on %s interface.\n", show_buff, show(show_buff), dev); 
                    
                    // unload structure trie
                    bool unloaded = unload();
    
                    // abort if trie not unloaded
                    if (!unloaded) 
                    {
                        printf("Could not unload trie %s.\n", dev);
                        exit(EXIT_FAILURE);
                    }
                }
                while(1) 
                {
                    strncpy(temp_shm, shm, 27);
                    if (strncmp(shm, "select ", 7) == 0 || strncmp(shm, "stat ", 5) == 0 || strcmp(shm, "help") == 0 || strcmp(shm, "start") == 0 || strcmp(shm, "quit") == 0 || (strcmp(shm, temp_shm) != 0 && strncmp(shm, "show ", 5) == 0))
                    {
                        break;
                    }
                }  
            }
            
            // select interface for sniffing
            if (strncmp(shm, "select ", 7) == 0)
            {
                while(1)
                {   
                    select_buff = strchr (shm, ' ') + 1;
                    for(int i = 0; i < 6; i++)
                    {
                        dev[i] = select_buff[i];
                    }
                    if (preset(dev) == false)
                    {
                        printf("Couldn't sniff on selected device! Print select [iface] for chosing new device or quit to exit\n");
                        
                        while(1)
                        {
                            strncpy(temp_shm, shm, 27);
                            if (strcmp(shm, "quit") == 0 || (strcmp(shm, temp_shm) != 0 && strncmp(shm, "select ", 7) == 0))
                                break;
                        }  
                    }
                    else
                    {
                        while (strcmp (shm, "start") != 0 && strncmp(shm, "stat ", 5) != 0 && strcmp(shm, "quit") != 0 && strcmp(shm, "help") != 0 && strncmp(shm, "show ", 5) != 0)                        
                        {
                        }
                        break;
                    }        
                }
            }
        }
    }
    else 
    {
        // fork failed
        printf("fork() failed!\n");
        return 1;
    }
    printf("Now exit!\n");
    cleanup();
    return 0;
}

// loading IP words from IP_log_sniff file to a trie struct
bool load(char* dev) 
{
    root = createNewNode();
    
    // defining current node pointing to root
    node* current = root;
    
    // opening log file for reading
    IP_log_sniff = fopen(dev, "r");
    
    // checking if file opens
    if (IP_log_sniff == NULL) 
    {
        return false;
    } 
    else 
    {
        int index = 0; // index for children[]
        char word[15 + 2]; // IP word + eol 192.168.001.001 = 15 
        while (true) 
        {
            //getting strings from IP_log_sniff one by one
            fgets(word, 15 + 2, IP_log_sniff);
            for (int i = 0; word[i] != 10; i++) // till the eol
            {
                if (word[i] == 46) // dot
                    index = 10;
                else
                    index = word[i] - 48; //asci code of 0 = 48
                current = insertSymbol(current, index);
            }

            if (feof(IP_log_sniff)) // till the eof
            {
                break;
            }
            current -> is_word = true;
            if (current -> is_word == true)
                current -> num_of_packets = (current -> num_of_packets) + 1;
            current = root;
        }
        fclose(IP_log_sniff);
        return true;
    }
}

int show(char* word) 
{
    // defining current node pointing to root
    node* current = root;
    int index = 0;
    int c = 0;
    for (int i = 0; i < 15 + 2; i++) // 15 - length of ip word
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
        } else
            current = current -> children[index];
    }
    printf("No such IP in the list\n");
    return 0;
}

// print out whole statistics
void statistics(node* node, int depth, char buff[]) 
{
    for (int i = 0; i < 11; i++) 
    {
        if (node -> children[i] != NULL) 
        {
            if (i == 10) // dot
                buff[depth] = '.';
            else // ascii code of 0 equals 48
                buff[depth] = i + 48;
            // recursevely calling stat function 
            statistics(node -> children[i], depth + 1, buff);
        } 
        else
            buff[depth] = '\0';
    }
    if (node -> is_word == true)
        printf("From %16s got %lu packets \n", buff, node -> num_of_packets);
}
