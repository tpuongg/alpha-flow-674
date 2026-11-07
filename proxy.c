#include "proxy.h"
#include "logger.h"

void load_proxies(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        LOG_WARN("Could not open proxies file: %s", filename);
        return;
    }
    proxies = malloc(sizeof(Proxy) * MAX_PROXIES);
    if (!proxies) {
        LOG_ERR("Failed to allocate memory for proxies!");
        fclose(fp);
        return;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (proxy_count >= MAX_PROXIES) break;

        char *start = line;
        while (*start == ' ' || *start == '\t') start++;

        int ptype = PROXY_TYPE_SOCKS5;
        if (strncmp(start, "socks5://", 9) == 0) { ptype = PROXY_TYPE_SOCKS5; start += 9; }
        else if (strncmp(start, "socks4://", 9) == 0) { ptype = PROXY_TYPE_SOCKS4; start += 9; }
        else if (strncmp(start, "https://", 8) == 0) { ptype = PROXY_TYPE_HTTP; start += 8; }
        else if (strncmp(start, "http://", 7) == 0)  { ptype = PROXY_TYPE_HTTP; start += 7; }

        char *h = strtok(start, ":\r\n");
        char *p = strtok(NULL, ":\r\n");
        char *u = strtok(NULL, ":\r\n");
        char *pw = strtok(NULL, ":\r\n");
        if (!h || !p) continue;

        memset(&proxies[proxy_count], 0, sizeof(Proxy));
        strncpy(proxies[proxy_count].host, h, sizeof(proxies[proxy_count].host) - 1);
        proxies[proxy_count].host[sizeof(proxies[proxy_count].host) - 1] = '\0';

        proxies[proxy_count].port = atoi(p);
        proxies[proxy_count].type = ptype;

        if (u && pw) {
            strncpy(proxies[proxy_count].user, u, sizeof(proxies[proxy_count].user) - 1);
            proxies[proxy_count].user[sizeof(proxies[proxy_count].user) - 1] = '\0';

            strncpy(proxies[proxy_count].pass, pw, sizeof(proxies[proxy_count].pass) - 1);
            proxies[proxy_count].pass[sizeof(proxies[proxy_count].pass) - 1] = '\0';

            proxies[proxy_count].has_auth = 1;
        }
        proxy_count++;
    }
    fclose(fp);
    LOG_INFO("Tornado Engine: Loaded %d strong proxies", proxy_count);
}
