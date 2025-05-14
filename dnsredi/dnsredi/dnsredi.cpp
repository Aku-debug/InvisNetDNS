#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <map>
#include <algorithm>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <random>
#include <cstring>
#include <string>
#include <locale>
#include <codecvt>
#include <memory> // For smart pointers

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wininet.lib")

#define SIO_RCVALL _WSAIOW(IOC_VENDOR, 1)
#define MAX_PACKET_SIZE 65536
#define DNS_PORT 53
#define HTTP_PORT 80
#define HTTPS_PORT 443

// Gerekli başlık yapıları
typedef struct _IPHEADER {
    unsigned char ihl : 4;
    unsigned char version : 4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
} IPHEADER;

typedef struct _TCPHEADER {
    unsigned short th_sport;
    unsigned short th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_x2 : 4;
    unsigned char doff : 4;  // Fixed: changed th_off to doff
    unsigned char th_flags;
    unsigned short th_win;
    unsigned short th_sum;
    unsigned short th_urp;
} TCPHEADER;

typedef struct _UDPHEADER {
    unsigned short uh_sport;
    unsigned short uh_dport;
    unsigned short uh_ulen;
    unsigned short uh_sum;
} UDPHEADER;

typedef struct _DNSHEADER {
    unsigned short id;
    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;
    unsigned char rcode : 4;
    unsigned char z : 3;
    unsigned char ra : 1;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} DNSHEADER;

class AdvancedBypassException : public std::exception {
private:
    std::string message;
public:
    AdvancedBypassException(const std::string& msg) : message(msg) {}
    virtual const char* what() const noexcept override {
        return message.c_str();
    }
};

std::atomic<bool> running(true);
std::map<std::string, std::string> domainMapping;
sockaddr_in destAddr;  // Added declaration for destAddr

// Rastgele sayı üreteci
std::string generateRandomString(size_t length) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);

    std::string s;
    s.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        s += alphanum[dis(gen)];
    }
    return s;;
}

// DNS önbelleğini temizle
void flushDNSCache() {
    system("ipconfig /flushdns");
    // Removed DnsFlushResolverCache() as it's not available
}

// TCP/IP stack'ini sıfırla
void resetTCPIPStack() {
    system("netsh int ip reset");
    system("netsh winsock reset");
}

// wchar_t* türünü std::string türüne dönüştürme fonksiyonu
std::string wide_to_narrow(const wchar_t* wstr)
{
    if (!wstr) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, nullptr, nullptr);
    return strTo;
}

// Prosesleri kontrol et (şüpheli analiz araçlarını tespit et)
bool detectAnalysisTools() {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false; // Failed to create snapshot
    }
    if (Process32First(snapshot, &entry)) {
        do {
            std::string processName = wide_to_narrow(entry.szExeFile); // Dönüşüm uygulandı
            std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

            // Analiz araçlarının listesi
            if (processName == "wireshark.exe" || processName == "fiddler.exe" ||
                processName == "processhacker.exe" || processName == "procmon.exe") {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return false;
}

// Domain mapping için rastgele alt domainler oluştur
void initializeDomainMapping() {
    domainMapping["google.com"] = generateRandomString(8) + ".google.com";
    domainMapping["youtube.com"] = generateRandomString(8) + ".youtube.com";
    domainMapping["facebook.com"] = generateRandomString(8) + ".facebook.com";
    // Diğer sık kullanılan domainleri ekleyebilirsiniz
}

// Paket manipülasyon teknikleri
void manipulatePacket(char* packet, int size, SOCKET sendSocket) {
    IPHEADER* ipHeader = (IPHEADER*)packet;
    TCPHEADER* tcpHeader = (TCPHEADER*)(packet + ipHeader->ihl * 4);

    // TCP paketi ise
    if (ipHeader->protocol == IPPROTO_TCP) {
        // TCP başlık manipülasyonu
        tcpHeader->th_seq = htonl(ntohl(tcpHeader->th_seq) + 12345);
        tcpHeader->th_ack = htonl(ntohl(tcpHeader->th_ack) + 54321);

        // TCP pencere boyutunu değiştir
        tcpHeader->th_win = htons(65535);

        // TCP zaman damgasını değiştir
        if (ipHeader->ihl * 4 + tcpHeader->doff * 4 + 12 <= size) {
            uint32_t* tcpTimestamp = (uint32_t*)(packet + ipHeader->ihl * 4 + tcpHeader->doff * 4 + 8);
            *tcpTimestamp = htonl(rand());
        }
    }

    // HTTP isteği ise
    if (ntohs(tcpHeader->th_dport) == HTTP_PORT && size > ipHeader->ihl * 4 + tcpHeader->doff * 4 + 10) {
        char* payload = packet + ipHeader->ihl * 4 + tcpHeader->doff * 4;

        // Host header manipülasyonu
        char* hostHeader = strstr(payload, "Host: ");
        if (hostHeader) {
            char* hostEnd = strstr(hostHeader, "\r\n");
            if (hostEnd) {
                std::string originalHost(hostHeader + 6, hostEnd - (hostHeader + 6));
                if (domainMapping.find(originalHost) != domainMapping.end()) {
                    std::string fakeHost = domainMapping[originalHost];
                    size_t hostLineLength = strlen("Host: ") + fakeHost.size() + strlen("\r\n");
                    if (hostLineLength <= (hostEnd - hostHeader + 2))
                        memcpy(hostHeader + 6, fakeHost.c_str(), fakeHost.size());
                }
            }
        }

        // HTTP header'larını karıştır
        char* userAgent = strstr(payload, "User-Agent: ");
        if (userAgent) {
            char* uaEnd = strstr(userAgent, "\r\n");
            if (uaEnd) {
                std::string newUA = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ";
                newUA += "(KHTML, like Gecko) Chrome/" + generateRandomString(2) + "." + generateRandomString(4) + " Safari/537.36\r\n";
                size_t newUALength = newUA.size();
                size_t originalUALength = uaEnd - userAgent;
                memmove(userAgent + newUALength, uaEnd, payload + size - uaEnd);
                memcpy(userAgent, newUA.c_str(), newUALength);
                size += newUALength - originalUALength;
            }
        }
    }

    // DNS sorgusu ise
    if (ipHeader->protocol == IPPROTO_UDP &&
        (ntohs(((UDPHEADER*)(packet + ipHeader->ihl * 4))->uh_dport) == DNS_PORT)) {
        DNSHEADER* dnsHeader = (DNSHEADER*)(packet + ipHeader->ihl * 4 + sizeof(UDPHEADER));
        dnsHeader->id = htons(rand() % 65535); // DNS ID'yi değiştir

        // DNS sorgusunu manipüle et (sadece basit bir örnek)
        if (size > ipHeader->ihl * 4 + sizeof(UDPHEADER) + sizeof(DNSHEADER) + 5) {
            char* dnsQuery = packet + ipHeader->ihl * 4 + sizeof(UDPHEADER) + sizeof(DNSHEADER);
            if (dnsQuery[0] > 0) {
                dnsQuery[0] ^= 0xFF; // Sorgu adını basitçe maskele
            }
        }
    }

    // Manipüle edilmiş paketi tekrar gönder
    sendto(sendSocket, packet, size, 0, (sockaddr*)&destAddr, sizeof(destAddr));
}

// Paket yakalama ve işleme döngüsü
void captureAndBypass(SOCKET sock, SOCKET sendSocket) {
    char packet[MAX_PACKET_SIZE];
    int result;

    while (running) {
        result = recv(sock, packet, MAX_PACKET_SIZE, 0);
        if (result > 0) {
            manipulatePacket(packet, result, sendSocket);
        }
        else if (result == SOCKET_ERROR) {
            if (WSAGetLastError() != WSAEWOULDBLOCK) {
                throw AdvancedBypassException("Paket alma hatası");
            }
        }
    }
}

// Tünelleme için raw soket oluştur
void startAdvancedBypass(const std::string& interfaceIp) {
    WSADATA wsaData;
    SOCKET recvSocket, sendSocket;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw AdvancedBypassException("WSAStartup başarısız");
    }

    // Alıcı soket
    recvSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (recvSocket == INVALID_SOCKET) {
        WSACleanup();
        throw AdvancedBypassException("Alıcı soket oluşturulamadı");
    }

    // Gönderici soket
    sendSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sendSocket == INVALID_SOCKET) {
        if (recvSocket != INVALID_SOCKET) {
            closesocket(recvSocket);
        }
        WSACleanup();
        throw AdvancedBypassException("Gönderici soket oluşturulamadı");
    }
    // Soket bağlama
    sockaddr_in sa;
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, interfaceIp.c_str(), &(sa.sin_addr)) != 1) {
        // Hata işleme
        closesocket(recvSocket);
        closesocket(sendSocket);
        WSACleanup();
        throw AdvancedBypassException("Geçersiz IP adresi");
    }
    sa.sin_port = htons(0);

    if (bind(recvSocket, (sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(recvSocket);
        closesocket(sendSocket);
        WSACleanup();
        throw AdvancedBypassException("Soket bağlantısı başarısız");
    }

    // Initialize destAddr for sending packets
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(0);
    destAddr.sin_addr.s_addr = INADDR_ANY;

    // Promiscuous mod
    DWORD dwValue = RCVALL_ON;
    if (WSAIoctl(recvSocket, SIO_RCVALL, &dwValue, sizeof(dwValue), NULL, 0, NULL, NULL, NULL) == SOCKET_ERROR) {
        closesocket(recvSocket);
        closesocket(sendSocket);
        WSACleanup();
        throw AdvancedBypassException("Promiscuous modu etkinleştirilemedi");
    }

    // IP_HDRINCL seçeneği (kendi IP başlığımızı oluşturmak için)
    dwValue = 1;
    if (setsockopt(sendSocket, IPPROTO_IP, IP_HDRINCL, (char*)&dwValue, sizeof(dwValue)) == SOCKET_ERROR) {
        closesocket(recvSocket);
        closesocket(sendSocket);
        WSACleanup();
        throw AdvancedBypassException("IP_HDRINCL ayarlanamadı");
    }

    // Paket yakalama ve işleme döngüsünü başlat
    try {
        captureAndBypass(recvSocket, sendSocket);
    }
    catch (...) {
        // Clean up sockets on exception
        closesocket(recvSocket);
        closesocket(sendSocket);
        WSACleanup();
        throw;
    }

    closesocket(recvSocket);
    closesocket(sendSocket);
    WSACleanup();
}

// Ağ arabirimlerini ve IP'lerini listele
std::map<std::string, std::string> getNetworkInterfacesWithIPs() {
    std::map<std::string, std::string> interfaces;
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = 0;
    DWORD dwRetVal = 0;

    // İlk olarak arabellek boyutunu öğrenmek için NULL ve 0 ile çağırın.
    dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        pAdapterInfo = (PIP_ADAPTER_INFO)malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            throw AdvancedBypassException("Bellek ayırma hatası");
        }
        dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        free(pAdapterInfo);
        if (dwRetVal == ERROR_NO_DATA)
        {
            return interfaces; //No adapters found, return empty map.
        }
        else
        {
            throw AdvancedBypassException("Ağ arabirimleri alınamadı");
        }
    }

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo; // Use a separate pointer for iteration
    while (pAdapter) {
        interfaces[pAdapter->Description] = pAdapter->IpAddressList.IpAddress.String;
        pAdapter = pAdapter->Next;
    }

    free(pAdapterInfo); // Free the memory allocated by GetAdaptersInfo
    return interfaces;
}

// CTRL+C handler
BOOL WINAPI consoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        running = false;
        return TRUE;
    }
    return FALSE;
}

int main() {
    try {
        // Analiz araçlarını tespit et
        auto detectAnalysisTools = []() -> bool {
            PROCESSENTRY32 entry;
            entry.dwSize = sizeof(PROCESSENTRY32);

            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
            if (snapshot == INVALID_HANDLE_VALUE) {
                return false; // Failed to create snapshot
            }
            if (Process32First(snapshot, &entry)) {
                do {
                    std::string processName = wide_to_narrow(entry.szExeFile);
                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);

                    // Analiz araçlarının listesi
                    if (processName == "wireshark.exe" || processName == "fiddler.exe" ||
                        processName == "processhacker.exe" || processName == "procmon.exe") {
                        CloseHandle(snapshot);
                        return true;
                    }
                } while (Process32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
            return false;
            };

        if (detectAnalysisTools()) {
            std::cerr << "Analiz aracı tespit edildi. Uygulama kapatılıyor." << std::endl;
            return 1;
        }

        // CTRL+C handler
        if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
            throw AdvancedBypassException("CTRL+C yakalayici ayarlanamadi");
        }

        // DNS ve TCP/IP optimizasyonları
        flushDNSCache();
        resetTCPIPStack();
        initializeDomainMapping();

        // Ağ arabirimlerini listele
        auto interfaces = getNetworkInterfacesWithIPs();
        if (interfaces.empty()) {
            throw AdvancedBypassException("Ağ arabirimi bulunamadı");
        }

        // Kullanıcı seçimi (ilk arabirimi otomatik seç - konsol çıktısı olmadığı için)
        if (!interfaces.empty()) {
            std::string selectedInterfaceIp = interfaces.begin()->second;
            std::cout << "Kullanilan Arayuz IP Adresi: " << selectedInterfaceIp << std::endl;
            // Bypass'ı başlat
            std::thread bypassThread(startAdvancedBypass, selectedInterfaceIp);
            bypassThread.join();
        }
        else
        {
            std::cout << "Ağ arabirimi bulunamadı." << std::endl;
        }

    }
    catch (const AdvancedBypassException& e) {
        std::cerr << "Hata: " << e.what() << std::endl;
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << "Beklenmeyen Hata: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
