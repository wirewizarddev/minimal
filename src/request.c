#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

#include "request.h"

static size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
  query_response *res = (query_response*)userdata;
  size_t realsize = size * nmemb;

  char *ptr_new = realloc(res->data, res->size + realsize + 1);
  if (!ptr_new) {
    return 0;
  }

  res->data = ptr_new;
  memcpy(&(res->data[res->size]), ptr, realsize);
  res->size += realsize;
  res->data[res->size] = '\0';

  return realsize;
}

char *curl_get_request(const char *endpoint) {
  CURL *curl;
  CURLcode res;

  query_response chunk;
  chunk.data = (char*)malloc(1);
  if (chunk.data == NULL) {
    perror("chunk.data: memory allocation error");
    return NULL;
  }
  chunk.size = 0;

  curl_global_init(CURL_GLOBAL_DEFAULT);
  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
      free(chunk.data);
      return NULL;
    }

    curl_easy_cleanup(curl);
  }

  curl_global_cleanup();

  return chunk.data;
}
