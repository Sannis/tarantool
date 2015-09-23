#ifndef   TARANTOOL_BOX_MEMCACHED_LAYER_H_INCLUDED
#define   TARANTOOL_BOX_MEMCACHED_LAYER_H_INCLUDED

void memcached_process_set     (struct memcached_connection *con);
void memcached_process_get     (struct memcached_connection *con);
void memcached_process_del     (struct memcached_connection *con);
void memcached_process_nop     (struct memcached_connection *con);
void memcached_process_flush   (struct memcached_connection *con);
void memcached_process_gat     (struct memcached_connection *con);
void memcached_process_version (struct memcached_connection *con);
void memcached_process_delta   (struct memcached_connection *con);
void memcached_process_pend    (struct memcached_connection *con);
void memcached_process_quit    (struct memcached_connection *con);
void memcached_process_stats   (struct memcached_connection *con);

void memcached_process_error(struct memcached_connection *con,
			     uint16_t err, const char *errstr);
void memcached_process_internal_error(struct memcached_connection *con);

#endif /* TARANTOOL_BOX_MEMCACHED_LAYER_H_INCLUDED */
