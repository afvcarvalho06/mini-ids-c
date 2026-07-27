#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h> // Necessário para a função exit()

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char ip_origem[INET_ADDRSTRLEN];
        char ip_destino[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), ip_origem, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), ip_destino, INET_ADDRSTRLEN);
        
        if (ip_header->ip_p == IPPROTO_TCP) {
            
            int ip_header_len = ip_header->ip_hl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            
            uint16_t porto_origem = ntohs(tcp_header->source);
            uint16_t porto_destino = ntohs(tcp_header->dest);
            
            // Só imprime alertas para mantermos o ecrã limpo de ruído e focado na deteção
            if (tcp_header->syn && !tcp_header->ack) {
                printf("[ALERTA] Conexao (SYN) para porto %d detetada! IP: %s\n", porto_destino, ip_origem);
                
                if (porto_destino == 22) {
                    printf("  >>> [CRÍTICO] Tentativa de acesso SSH na interface!\n");
                }
            }
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *interface = "enp0s3"; // A tua interface de rede

    printf("=== Mini-IDS: Fase 5 - Escuta ao Vivo (%s) ===\n\n", interface);

    // pcap_open_live(interface, BUFSIZ (limite pacote), Modo Promíscuo(1=sim), timeout_ms, buffer erro)
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Falha ao abrir o dispositivo %s: %s\n", interface, errbuf);
        printf("Tens a certeza que corres o programa com 'sudo'?\n");
        return 1;
    }

    printf("Sentinela ativa! A aguardar ataques...\n\n");

    // Ciclo contínuo de captura (-1 instrui captura indefinida)
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    
    return 0;
}