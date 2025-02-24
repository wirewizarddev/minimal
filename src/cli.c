#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "request.h"
#include "wireguard.h"

/**
 * @param char folder path.
 * @return 0 if the directory exists and 1 if it does not.
 */
static int dir_exists(const char *path) {
  struct stat info;

  if (stat(path, &info) != 0) {
    perror("error when trying to find a folder");
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  #ifdef TEMPDIR
    int dir = dir_exists(TMP_WG_PATH);
  #else
    int dir = dir_exists(WG_PATH);
  #endif
  if (dir != 0) exit(1);

  static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"add", required_argument, 0, 'a'},
    {0, 0, 0, 0},
  };

  wireguard_settings* wgs = (wireguard_settings*)malloc(sizeof(wireguard_settings));
  if (wgs == NULL) {
    perror("main wgs: memory allocation error");
    exit(1);
  }
  wg_settings_init(wgs);

  char *server = NULL, *publicip = NULL;

  int index = 0;
  while ((index = getopt_long(argc, argv, "ha:", long_options, NULL)) != -1) {
    switch (index) {
      case 'h':
        printf(
          "WireWizard: minimal version\n"
          "author: heycatch\n"
          "\nAvailable options:\n"
          "-h, --help                              Display information about all flags\n"
          "--------------------------------------------\n"
          "-a, --add    [server|client] [yes|no]   Create a wireguard server/client configuration\n"
          "                                        After the name, specify whether to add DNS\n"
          "       * ww --add server null\n"
          "       * ww --add client [yes|no]\n");
        break;
      case 'a':
        if (optind + 1 == argc) {
          if (strcmp(argv[2], "server") == 0) {
            if (wg_init_settings_server(wgs->name, wgs->subnetwork, wgs->port) == 0) {
              wg_generate_keys(wgs);
              wg_create_config_server(wgs);
              printf("\033[31mALERT\033[0m");
              printf(": if you are using a firewall, be sure to open port ");
              printf("\033[32m%s\033[0m", wgs->port);
              printf("\n");
              #ifdef BASHENABLE
                wg_start_systemctl(wgs->name);
              #endif
            }
          } else if (strcmp(argv[2], "client") == 0) {
            if (strlen(optarg) >= 64) break;
            strcpy(wgs->name, optarg);
            publicip = curl_get_request("https://ifconfig.me/ip");
            if (publicip != NULL) {
              if (wg_client_count_on_servers(&server) == 0) {
                #ifdef BASHENABLE
                  wg_stop_server(server);
                #endif
                wg_generate_keys(wgs);
                wg_generate_pub_key(wgs, server);
                if (wg_init_settings_client(server, wgs->subnetwork, wgs->port) == 0) {
                  wg_add_client_in_config(wgs, server);
                  wg_create_config_client(wgs, publicip, argv[3]);
                }
                #ifdef BASHENABLE
                  wg_start_server(server);
                #endif
              }
            }
            free(publicip);
            free(server);
          }
        }
        break;
      default:
        printf("wrong parse: use --help for details\n");
        wg_settings_free_memory(wgs);
        /*
         * In this case we need exit(1), because without it we will try to
         * involuntarily execute other flags in case of incorrect input.
         */
        exit(1);
    }
  }

  wg_settings_free_memory(wgs);

  return 0;
}
