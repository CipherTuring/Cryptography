idf_component_register(SRCS "main.c" "net.c" "crypto.c" "protocol.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES console esp_event esp_netif esp_timer esp_wifi lwip mbedtls nvs_flash)
