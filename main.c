#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <time.h>

# define IPV4LEN 16

struct fiveTuple {
    char src_ip[IPV4LEN];
    char dst_ip[IPV4LEN];
    int src_port;
    int dst_port;
    int protocol;
};

struct fiveTupleArray {
    struct fiveTuple name;
    long count;
};

struct fiveTupleArray tuples[100000];
int tuple_count = 0;



void save_packet_to_tuples(const char *src_ip, const char *dst_ip, int src_port, int dst_port, int proto)
{
    // Поиск существующего
    for (int i = 0; i < tuple_count; i++) {
        if (strcmp(tuples[i].name.src_ip, src_ip) == 0 &&
            strcmp(tuples[i].name.dst_ip, dst_ip) == 0 &&
            tuples[i].name.src_port == src_port &&
            tuples[i].name.dst_port == dst_port &&
            tuples[i].name.protocol == proto) {
            tuples[i].count++;
            return;
        }
    }

    // Добавление нового
        struct fiveTupleArray *p_arr = &tuples[tuple_count];
        strncpy(p_arr->name.src_ip, src_ip, IPV4LEN - 1);
        strncpy(p_arr->name.dst_ip, dst_ip, IPV4LEN - 1);
        p_arr->name.src_port = src_port;
        p_arr->name.dst_port = dst_port;
        p_arr->name.protocol = proto;
        p_arr->count = 1;
        tuple_count++;
}





void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet){
    // Пропускаем Ethernet заголовок 
    const struct ether_header *l2 = (const struct ether_header *)packet;
    if (ntohs(l2->ether_type) != ETHERTYPE_IP) return;

    const struct ip *ip = (const struct ip *)(packet + sizeof(struct ether_header));
    
    // Пропускаем не TCP/UDP
    if (ip->ip_p != IPPROTO_TCP && ip->ip_p != IPPROTO_UDP) return;

    char src_ip[IPV4LEN], dst_ip[IPV4LEN];
    inet_ntop(AF_INET, &ip->ip_src, src_ip, IPV4LEN);   // Address Family IPv4
    inet_ntop(AF_INET, &ip->ip_dst, dst_ip, IPV4LEN);

    int ip_header_len = ip->ip_hl * 4;
    const unsigned char *transport = packet + sizeof(struct ether_header) + ip_header_len;

    int src_port = 0, dst_port = 0;

    if (ip->ip_p == IPPROTO_TCP) {
        if (pkthdr->caplen >= sizeof(struct ether_header) + ip_header_len + sizeof(struct tcphdr)) {
            const struct tcphdr *tcp = (const struct tcphdr *)transport;
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
        } else return;
    }
    else if (ip->ip_p == IPPROTO_UDP) {
        if (pkthdr->caplen >= sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr)) {
            const struct udphdr *udp = (const struct udphdr *)transport;
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
        } else return;
    }

    // Игнорируем пакеты с нулевыми портами (маловероятно, но на всякий)
    if (src_port == 0 || dst_port == 0) return;

    save_packet_to_tuples(src_ip, dst_ip, src_port, dst_port, ip->ip_p);
}



int main(int argc, char const *argv[])
{
    const char *iname = NULL;
    int time_packets = 0;
    int count_packets = 0;
    const char *filename = NULL;
    short flag = 0;
    
    for (size_t i = 1; i < argc; i++)
    {
        if(strcmp(argv[i],"-i")==0) {           // arg -i
            if(argc>i+1){
                iname = argv[i+1];
                i++;
            }
        }
        else if(strcmp(argv[i],"-f")==0) {      // arg -f
            if(argc>i+1){
                filename = argv[i+1];
                i++;
            }
        }
        else if(strcmp(argv[i],"-t")==0) {      // arg -t
            if (flag == 0){
                if(argc>i+1){
                    const char *time = argv[i+1];
                    time_packets = atoi(time);
                    i++;
                    flag = 1;
                }
            }
            else {
                printf("Only one argument -t or -c applied\n");
                return 1;
            }
        }
        else if(strcmp(argv[i],"-c")==0) {      // arg -c
            if (flag == 0){
                if(argc>i+1){
                    const char *count = argv[i+1];
                    count_packets = atoi(count);
                    i++;
                    flag = 1;
                }
            }
            else {
                printf("Only one argument -t or -c applied\n");
                return 1;
            }
        }
    }
    
    // вывод на экран аргументов
    printf("interface: %s, time: %d, count packets: %d, filename: %s\n", iname, time_packets, count_packets, filename);
    
    char error_buffer[PCAP_ERRBUF_SIZE];

    // создаем обработчик, передаем:
    // имя интерфейса, сколько байт читать с каждого пакета, 1 мод(слушать все пакеты), время ожидание новых пакетов, буфер ошибок
    pcap_t *handle = pcap_open_live(iname, BUFSIZ, 1, 1000, error_buffer);
    if (handle==NULL){
        printf("Error opening interface %s: %s", iname, error_buffer);
        return 1;
    }
    if (time_packets > 0){
        time_t start_t = time(NULL);
        while(difftime(time(NULL), start_t)<time_packets){
            pcap_dispatch(handle, 0, packet_handler, NULL);
        }
    }
    else{
        // запускаем прослушку пакетов, передаем:
        // обработчик, ограничение по пакетам, функцию по обработке пакетов, доп.данные
        pcap_loop(handle, count_packets, packet_handler, NULL);
    }
    pcap_close(handle);
    
    if (filename) {
        FILE *csv = fopen(filename, "w");
        if (csv) {
            fprintf(csv, "src_ip,dst_ip,src_port,dst_port,protocol,packet_count\n");
            for (int i = 0; i < tuple_count; i++) {
                fprintf(csv, "%s,%s,%d,%d,%d,%ld\n",
                    tuples[i].name.src_ip,
                    tuples[i].name.dst_ip,
                    tuples[i].name.src_port,
                    tuples[i].name.dst_port,
                    tuples[i].name.protocol,
                    tuples[i].count
                );
            }
            fclose(csv);
        }
    }
    
    return 0;
}

