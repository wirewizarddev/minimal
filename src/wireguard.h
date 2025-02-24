#ifndef WIREGUARD_H
#define WIREGUARD_H

#define TMP "/tmp/"
#define TMP_WG_PATH "/tmp/wireguard/"
#define WG_PATH "/etc/wireguard/"

typedef struct {
  char *name;
  char *subnetwork;
  char *port;
  char *priv_key_hash;
  char *pub_key_hash;
  char *pub_temp_hash;
} wireguard_settings;

/**
 * @param struct wireguard_settings with all user information.
 */
void wg_settings_init(wireguard_settings *wgs);

/**
 * @param struct wireguard_settings with all user information.
 */
void wg_settings_free_memory(wireguard_settings *wgs);

/**
 * @param struct shortened server name.
 */
void wg_stop_systemctl(const char *user);

/**
 * @param struct shortened server name.
 */
void wg_start_systemctl(const char *user);

/**
 * @param struct shortened server name.
 */
void wg_stop_server(const char *user);

/**
 * @param char shortened server name.
 */
void wg_start_server(const char *user);

/**
 * Maximum number of network interfaces from wg0 to wg9 and
 * subnetworks from 10.0.0.1/28 to 10.0.9.1/28.
 *  
 * @param char wg interface name.
 * @param char subnetwork pointer from [Interface].
 * @param char port pointer from [Interface].
 * @return 0 if successful and 1 on error.
 */
int wg_init_settings_server(char *server, char *subnetwork, char *port);

/**
 * 32 bits - 28 bits of mask = 4 bits for hosts. 2^4 = 16 IP addresses in total.
 * Reserved addresses: network address (10.0.x.0) / broadcast address (10.0.x.15).
 * Available addresses for the client from 10.0.x.2/32 to 10.0.x.14/32.
 * 
 * @param char wg interface name.
 * @param char subnetwork pointer from [Peer].
 * @param char port pointer from [Interface].
 * @return 0 if successful and 1 on error.
 */
int wg_init_settings_client(const char *server, char *subnetwork, char *port);

/**
 * You'll need to select a server from the list.
 * 
 * @param char wg interface name.
 * @return 0 if successful and 1 on error.
 */
int wg_client_count_on_servers(char **server);

/**
 * @param struct wireguard_settings with all user information.
 * @param char private key pointer generated from [Interface].
 */
void wg_generate_pub_key(wireguard_settings *wgs, const char *server);

/**
 * @param struct wireguard_settings with all user information.
 */
void wg_generate_keys(wireguard_settings *wgs);

/**
 * @param struct wireguard_settings with all user information.
 */
void wg_create_config_server(wireguard_settings *wgs);

/**
 * @param struct wireguard_settings with all user information.
 * @param char public ip from get_ip_address().
 * @param char yes/no to the question about adding dns.
 */
void wg_create_config_client(wireguard_settings *wgs, const char *publicip, const char *issue);

/**
 * @param struct wireguard_settings with all user information.
 * @param char name of the config to which the client will be added.
 */
void wg_add_client_in_config(wireguard_settings *wgs, const char *config_name);

#endif
