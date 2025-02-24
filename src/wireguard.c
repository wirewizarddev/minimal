#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <ctype.h>

#include "mask.h"
#include "wireguard.h"

void wg_settings_init(wireguard_settings *wgs) {
  wgs->name = (char*)malloc(64);
  if (wgs->name == NULL) {
    perror("wgs->name: memory allocation error");
    return;
  }

  wgs->subnetwork = (char*)malloc(64);
  if (wgs->subnetwork == NULL) {
    perror("wgs->subnetwork: memory allocation error");
    wg_settings_free_memory(wgs);
    return;
  }

  wgs->port = (char*)malloc(32);
  if (wgs->port == NULL) {
    perror("wgs->port: memory allocation error");
    wg_settings_free_memory(wgs);
    return;
  }

  wgs->priv_key_hash = (char*)malloc(64);
  if (wgs->priv_key_hash == NULL) {
    perror("wgs->priv_key_hash: memory allocation error");
    wg_settings_free_memory(wgs);
    return;
  }

  wgs->pub_key_hash = (char*)malloc(64);
  if (wgs->pub_key_hash == NULL) {
    perror("wgs->pub_key_hash: memory allocation error");
    wg_settings_free_memory(wgs);
    return;
  }

  wgs->pub_temp_hash = (char*)malloc(64);
  if (wgs->pub_temp_hash == NULL) {
    perror("wgs->pub_temp_hash: memory allocation error");
    wg_settings_free_memory(wgs);
    return;
  }
}

void wg_settings_free_memory(wireguard_settings *wgs) {
  if (wgs != NULL) {
    if (wgs->name != NULL) {
      free(wgs->name);
    }
    if (wgs->subnetwork != NULL) {
      free(wgs->subnetwork);
    }
    if (wgs->port != NULL) {
      free(wgs->port);
    }
    if (wgs->priv_key_hash != NULL) {
      free(wgs->priv_key_hash);
    }
    if (wgs->pub_key_hash != NULL) {
      free(wgs->pub_key_hash);
    }
    if (wgs->pub_temp_hash != NULL) {
      free(wgs->pub_temp_hash);
    }
    free(wgs);
  }
}

/**
 * Works with IPv4 only.
 * 
 * @return the name of the network inteface or NULL.
 */
static char *return_interface_name() {
  struct ifaddrs *ifap, *ifa;
  char *interface = NULL;

  if (getifaddrs(&ifap) == -1) return NULL;

  for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL) continue;
    /*
     * IPv6 address family(AF_INET6), localhost, docker and wireguard skipping.
     * At the moment we have made a stub for 10 interfaces per server wg0-wg9.
     */
    if (ifa->ifa_addr->sa_family == AF_INET &&
        strcmp(ifa->ifa_name, "lo") != 0 &&
        strcmp(ifa->ifa_name, "docker0") != 0 &&
        strcmp(ifa->ifa_name, "wg0") != 0 &&
        strcmp(ifa->ifa_name, "wg1") != 0 &&
        strcmp(ifa->ifa_name, "wg2") != 0 &&
        strcmp(ifa->ifa_name, "wg3") != 0 &&
        strcmp(ifa->ifa_name, "wg4") != 0 &&
        strcmp(ifa->ifa_name, "wg5") != 0 &&
        strcmp(ifa->ifa_name, "wg6") != 0 &&
        strcmp(ifa->ifa_name, "wg7") != 0 &&
        strcmp(ifa->ifa_name, "wg8") != 0 &&
        strcmp(ifa->ifa_name, "wg9") != 0) {
      interface = strdup(ifa->ifa_name);
      if (interface == NULL) {
        perror("interface: memory allocation error");
        freeifaddrs(ifap);
        return NULL;
      }
      break;
    }
  }

  freeifaddrs(ifap);

  return interface;
}

/**
 * @param char hash path.
 * @param char pointer to which the hash will be written.
 */
static int wg_read_hash(const char *path, char **hash) {
  FILE *file = fopen(path, "r");
  if (file == NULL) {
    perror("file reading error");
    return 1;
  }

  if (fgets(*hash, 64, file) == NULL) {
    perror("reading hash error");
    fclose(file);
    return 1;
  }
  
  (*hash)[strcspn(*hash, "\n")] = '\0';

  fclose(file);

  return 0;
}

void wg_stop_systemctl(const char *user) {
  char shell_stop[256], shell_disable[256];

  snprintf(shell_stop, 256, "systemctl stop wg-quick@%s", user);
  snprintf(shell_disable, 256, "systemctl disable wg-quick@%s", user);

  if (system(shell_stop) != 0 || system(shell_disable) != 0) {
    perror("systemctl: the service doesn not stop or disabled");
    return;
  }

  printf("service ");
  printf("\033[32mwg-quick@%s\033[0m", user);
  printf(" is stopped and disabled\n");
}

void wg_start_systemctl(const char *user) {
  char shell_enable[256], shell_start[256];

  snprintf(shell_enable, 256, "systemctl enable wg-quick@%s", user);
  snprintf(shell_start, 256, "systemctl start wg-quick@%s", user);

  if (system(shell_enable) != 0 || system(shell_start) != 0) {
    perror("systemctl: couldn't get the service up and running");
    return;
  }

  printf("service ");
  printf("\033[32mwg-quick@%s\033[0m", user);
  printf(" is up and running\n");
}

void wg_stop_server(const char *user) {
  char shell[256];

  snprintf(shell, 256, "wg-quick down %s  > /dev/null 2>&1", user);

  if (system(shell) != 0) {
    perror("couldn't stop the server");
    return;
  }

  printf("server ");
  printf("\033[32m%s\033[0m", user);
  printf(" is down\n");
}

void wg_start_server(const char *user) {
  char shell[256];

  snprintf(shell, 256, "wg-quick up %s > /dev/null 2>&1", user);

  if (system(shell) != 0) {
    perror("couldn't get the server running");
    return;
  }

  printf("server ");
  printf("\033[32m%s\033[0m", user);
  printf(" is running\n");
}

void wg_generate_keys(wireguard_settings *wgs) {
  char priv_key_path[256], pub_key_path[256], shell[1024];

  snprintf(priv_key_path, 256, "%sprivatekey.%s", TMP, wgs->name);
  snprintf(pub_key_path, 256, "%spublickey.%s", TMP, wgs->name);
  snprintf(shell, 1024,
    "wg genkey | tee %s | wg pubkey | tee %s > /dev/null", priv_key_path, pub_key_path);

  if (system(shell) != 0) {
    perror("keys failed to generate");
    return;
  }

  printf("keys for ");
  printf("\033[32m%s\033[0m", wgs->name);
  printf(" generated\n");

  if (wg_read_hash(priv_key_path, &wgs->priv_key_hash) == 0 &&
      wg_read_hash(pub_key_path, &wgs->pub_key_hash) == 0)
    if (unlink(priv_key_path) != 0 || unlink(pub_key_path) != 0)
      perror("failed to delete file");
}

void wg_generate_pub_key(wireguard_settings *wgs, const char *server) {
  char conf[512];

  #ifdef TEMPDIR
    snprintf(conf, 512, "%s%s.conf", TMP_WG_PATH, server);
  #else
    snprintf(conf, 512, "%s%s.conf", WG_PATH, server);
  #endif

  FILE *file = fopen(conf, "r");
  if (file == NULL) {
    perror("file openning error");
    return;
  }

  char buffer_temp[256], buffer_priv_key[64];

  while (fgets(buffer_temp, 256, file) != NULL) {
    if (strncmp(buffer_temp, "PrivateKey = ", 13) == 0) {
      strncpy(buffer_priv_key, buffer_temp + 13, 64);
      buffer_priv_key[63] = '\0';
      break;
    }
  }

  fclose(file);

  char pub_key_path[256], shell[512];

  snprintf(pub_key_path, 256, "%spublickey.%s", TMP, server);
  snprintf(shell, 512, "echo '%s' | wg pubkey > %s", buffer_priv_key, pub_key_path);

  if (system(shell) != 0) {
    perror("keys failed to generate");
    return;
  }

  printf("public key for ");
  printf("\033[32m%s\033[0m", server);
  printf(" generated\n");

  if (wg_read_hash(pub_key_path, &wgs->pub_temp_hash) == 0)
    if (unlink(pub_key_path) != 0)
      perror("failed to delete file");
}

void wg_create_config_server(wireguard_settings *wgs) {
  char conf[512];

  #ifdef TEMPDIR
    snprintf(conf, 512, "%s%s.conf", TMP_WG_PATH, wgs->name);
  #else
    snprintf(conf, 512, "%s%s.conf", WG_PATH, wgs->name);
  #endif

  int fd = open(conf, O_WRONLY | O_CREAT | O_TRUNC, 0700);
  if (fd == -1) {
    perror("file creation error");
    return;
  }
  close(fd);

  FILE *fp = fopen(conf, "w");
  if (fp == NULL) {
    perror("file openning error");
    return;
  }

  char *interface = return_interface_name();

  char address[64], listenPort[64], privateKey[128], postUp[256], postDown[256];

  snprintf(address, 64, "Address = %s/%d\n", wgs->subnetwork, MASK_SERVER);
  snprintf(listenPort, 64, "ListenPort = %s\n", wgs->port);
  snprintf(privateKey, 128, "PrivateKey = %s\n", wgs->priv_key_hash);
  snprintf(postUp, 256, "PostUp = iptables -A FORWARD -i %%i -j ACCEPT; \
iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", interface);
  snprintf(postDown, 256, "PostDown = iptables -D FORWARD -i %%i -j ACCEPT; \
iptables -t nat -D POSTROUTING -o %s -j MASQUERADE\n", interface);

  fputs("[Interface]\n", fp);
  fputs(address, fp);
  fputs(listenPort, fp);
  fputs(privateKey, fp);
  fputs("SaveConfig = true\n", fp);
  fputs(postUp, fp);
  fputs(postDown, fp);
  fputs("MTU = 1420\n", fp);

  printf("\033[32m%s\033[0m", wgs->name);
  printf(" config has been created\n");

  fclose(fp);

  free(interface);
}

void wg_create_config_client(wireguard_settings *wgs, const char *publicip, const char *issue) {
  char conf[512];

  snprintf(conf, 512, "%s%s.conf", TMP, wgs->name);

  int fd = open(conf, O_WRONLY | O_CREAT | O_TRUNC, 0664);
  if (fd == -1) {
    perror("file creation error");
    return;
  }
  close(fd);

  FILE *fp = fopen(conf, "w");
  if (fp == NULL) {
    perror("file openning error");
    return;
  }

  char address[64], privateKey[128], publicKey[128], endpoint[256];

  snprintf(address, 64, "Address = %s\n", wgs->subnetwork);
  snprintf(privateKey, 128, "PrivateKey = %s\n", wgs->priv_key_hash);
  snprintf(publicKey, 128, "PublicKey = %s\n", wgs->pub_temp_hash);
  snprintf(endpoint, 256, "Endpoint = %s:%s\n", publicip, wgs->port);

  fputs("[Interface]\n", fp);
  fputs(address, fp);
  fputs(privateKey, fp);
  if (strcmp(issue, "yes") == 0) fputs("DNS = 1.1.1.1\n", fp);
  fputs("\n", fp);
  fputs("[Peer]\n", fp);
  fputs(publicKey, fp);
  fputs(endpoint, fp);
  fputs("AllowedIPs = 0.0.0.0/0\n", fp);
  fputs("PersistentKeepalive = 20\n", fp);

  printf("\033[32m%s.conf\033[0m", wgs->name);
  printf(" has been created and is located in the ");
  printf("\033[31m%s\033[0m", TMP);
  printf("\n");

  fclose(fp);

  char shell[512];

  snprintf(shell, 512, "qrencode -t ansiutf8 -s 1 -l L < %s%s.conf", TMP, wgs->name);

  if (system(shell) != 0) {
    perror("couldn't generate qrcode");
    return;
  }
}

void wg_add_client_in_config(wireguard_settings *wgs, const char *config_name) {
  char conf[512];

  #ifdef TEMPDIR
    snprintf(conf, 512, "%s%s.conf", TMP_WG_PATH, config_name);
  #else
    snprintf(conf, 512, "%s%s.conf", WG_PATH, config_name);
  #endif

  FILE *fp = fopen(conf, "a");
  if (fp == NULL) {
    perror("file openning error");
    return;
  }

  char publicKey[128], allowedIPs[128];

  snprintf(publicKey, 128, "PublicKey = %s\n", wgs->pub_key_hash);
  snprintf(allowedIPs, 128, "AllowedIPs = %s\n", wgs->subnetwork);

  fputs("\n[Peer]\n", fp);
  fputs(publicKey, fp);
  fputs(allowedIPs, fp);

  fclose(fp);

  printf("\033[32m%s\033[0m", wgs->name);
  printf(" has been added to the config\n");
}

int wg_init_settings_server(char *server, char *subnetwork, char *port) {
  #ifdef TEMPDIR
    DIR *dir = opendir(TMP_WG_PATH);
  #else
    DIR *dir = opendir(WG_PATH);
  #endif
  if (dir == NULL) return 1;

  struct dirent *entry;

  for (int i = 0; i < 10; i++) {
    char buffer_server[16];
    snprintf(buffer_server, 16, "wg%d.conf", i);

    rewinddir(dir);
    while ((entry = readdir(dir)) != NULL) {
      if (strcmp(entry->d_name, buffer_server) == 0)
        break;
    }

    if (entry == NULL) {
      snprintf(server, 64, "wg%d", i);
      snprintf(subnetwork, 64, "10.0.%d.1", i);
      snprintf(port, 32, "%d", PORT+i);
      return 0;
    }
  }

  return 1;
}

int wg_init_settings_client(const char *server, char *subnetwork, char *port) {
  char conf[512];

  #ifdef TEMPDIR
    snprintf(conf, 512, "%s%s.conf", TMP_WG_PATH, server);
  #else
    snprintf(conf, 512, "%s%s.conf", WG_PATH, server);
  #endif

  int server_number = 0;
  for (const char *s = server; *s != '\0'; s++)
    if (isdigit(*s))
      server_number = server_number * 10 + (*s - '0');

  snprintf(port, 32, "%d", PORT+server_number);

  for (int i = 2; i <= 14; i++) {
    FILE *file = fopen(conf, "r");
    if (file == NULL) {
      perror("file reading error");
      return -1;
    }

    int flag = 1;
    char buffer[256], buffer_temp[128];

    snprintf(buffer_temp, 128,
      "AllowedIPs = 10.0.%d.%d/%d\n", server_number, i, MASK_CLIENT);

    while (fgets(buffer, 256, file) != NULL) {
      if (strcmp(buffer, buffer_temp) == 0) {
        flag = 0;
        break;
      }
    }

    fclose(file);

    if (flag == 1) {
      snprintf(subnetwork, 64, "10.0.%d.%d/%d", server_number, i, MASK_CLIENT);
      return 0;
    }
  }

  return 1;
}

/**
 * The number of users in the configuration file.
 * 
 * @param char configuration file.
 * @return 0-14 the number of users or -1 on error.
 */
static int number_of_users(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (file == NULL) {
    perror("file reading error");
    return -1;
  }

  int count = 0;
  char buffer[512];

  while (fgets(buffer, 512, file) != NULL) {
    buffer[strcspn(buffer, "\n")] = 0;
    if (strcmp(buffer, "[Peer]") == 0) count++;
  }

  fclose(file);

  return count;
}

int wg_client_count_on_servers(char **server) {
  #ifdef TEMPDIR
    DIR *dir = opendir(TMP_WG_PATH);
  #else
    DIR *dir = opendir(WG_PATH);
  #endif
  if (dir == NULL) return 1;

  struct dirent *entry;

  int flag = 1;
  int count = 0;
  char buffer_path[512];

  while ((entry = readdir(dir)) != NULL) {
    if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      #ifdef TEMPDIR
        snprintf(buffer_path, 512, "%s%s", TMP_WG_PATH, entry->d_name);
      #else
        snprintf(buffer_path, 512, "%s%s", WG_PATH, entry->d_name);
      #endif

      count = number_of_users(buffer_path);
      if (count == -1) return 1;
      
      flag = 0;

      printf(">server: ");
      if (strlen(entry->d_name) > 5) entry->d_name[strlen(entry->d_name)-5] = '\0';
      printf("\033[32m%s\033[0m\n", entry->d_name);
      printf("          |__ clients: ");
      printf("\033[31m%d\033[0m", count);
      printf("/14\n");
    }
  }

  // The flag signals that the folder was empty.
  if (flag == 1) {
    perror("configuration files not found");
    return 1;
  }

  printf("Select a server: ");

  char buffer[16];
  if (fgets(buffer, 16, stdin) != NULL) {
    if (strlen(buffer) > 16) {
      perror("input string is too long\n");
      return 1;
    }
    buffer[strcspn(buffer, "\n")] = 0;
    *server = malloc(16);
    if (*server == NULL) {
      perror("*user: memory allocation error");
      return 1;
    }
    strncpy(*server, buffer, 16);
    (*server)[15] = '\0';
  } else {
    perror("error reading buffer");
    return 1;
  }

  return 0;
}
