#ifndef REQUEST_H
#define REQUEST_H

typedef struct {
  char *data;
  size_t size;
} query_response;

/**
 * @param char final endpoint for the search.
 * @return char the public IP of the server.
 */
char *curl_get_request(const char *endpoint);

#endif
