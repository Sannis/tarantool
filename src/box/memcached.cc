/*
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "say.h"
#include "cbus.h"
#include "coio.h"
#include "evio.h"
#include "main.h"
#include "fiber.h"
#include "iobuf.h"
#include "bit/bit.h"
#include "session.h"
#include "coio_buf.h"
#include "scoped_guard.h"

#include "memcached.h"
#include "memcached_layer.h"

static int
memcached_process_request(struct memcached_connection *con) {
	if (con->noprocess)
		goto noprocess;
	try {
		/* Process message */
		con->noreply = false;
		switch (con->hdr->cmd) {
		case (MEMCACHED_BIN_CMD_ADDQ):
		case (MEMCACHED_BIN_CMD_SETQ):
		case (MEMCACHED_BIN_CMD_REPLACEQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_ADD):
		case (MEMCACHED_BIN_CMD_SET):
		case (MEMCACHED_BIN_CMD_REPLACE):
			memcached_process_set(con);
			break;
		case (MEMCACHED_BIN_CMD_GETQ):
		case (MEMCACHED_BIN_CMD_GETKQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_GET):
		case (MEMCACHED_BIN_CMD_GETK):
			memcached_process_get(con);
			break;
		case (MEMCACHED_BIN_CMD_DELETEQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_DELETE):
			memcached_process_del(con);
			break;
		case (MEMCACHED_BIN_CMD_NOOP):
			memcached_process_nop(con);
			break;
		case (MEMCACHED_BIN_CMD_QUITQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_QUIT):
			memcached_process_quit(con);
			break;
		case (MEMCACHED_BIN_CMD_FLUSHQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_FLUSH):
			memcached_process_flush(con);
			break;
		case (MEMCACHED_BIN_CMD_STAT):
			memcached_process_stats(con);
			break;
		case (MEMCACHED_BIN_CMD_GATQ):
		case (MEMCACHED_BIN_CMD_GATKQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_GAT):
		case (MEMCACHED_BIN_CMD_GATK):
		case (MEMCACHED_BIN_CMD_TOUCH):
			memcached_process_gat(con);
			break;
		case (MEMCACHED_BIN_CMD_VERSION):
			memcached_process_version(con);
			break;
		case (MEMCACHED_BIN_CMD_INCRQ):
		case (MEMCACHED_BIN_CMD_DECRQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_INCR):
		case (MEMCACHED_BIN_CMD_DECR):
			memcached_process_delta(con);
			break;
		case (MEMCACHED_BIN_CMD_APPENDQ):
		case (MEMCACHED_BIN_CMD_PREPENDQ):
			con->noreply = true;
		case (MEMCACHED_BIN_CMD_APPEND):
		case (MEMCACHED_BIN_CMD_PREPEND):
			memcached_process_pend(con);
			break;
		case (MEMCACHED_BIN_CMD_SASL_LIST_MECHS):
		case (MEMCACHED_BIN_CMD_SASL_AUTH):
		case (MEMCACHED_BIN_CMD_SASL_STEP):
		case (MEMCACHED_BIN_CMD_RGET):
		case (MEMCACHED_BIN_CMD_RSETQ):
		case (MEMCACHED_BIN_CMD_RSET):
		case (MEMCACHED_BIN_CMD_RAPPENDQ):
		case (MEMCACHED_BIN_CMD_RAPPEND):
		case (MEMCACHED_BIN_CMD_RPREPENDQ):
		case (MEMCACHED_BIN_CMD_RPREPEND):
		case (MEMCACHED_BIN_CMD_RDELETEQ):
		case (MEMCACHED_BIN_CMD_RDELETE):
		case (MEMCACHED_BIN_CMD_RINCRQ):
		case (MEMCACHED_BIN_CMD_RINCR):
		case (MEMCACHED_BIN_CMD_RDECRQ):
		case (MEMCACHED_BIN_CMD_RDECR): {
			char errstr[257];
			size_t errlen = snprintf(errstr, 256,
				"Unsupported command '%s'",
				memcached_get_command_name(con->hdr->cmd)
			); (void )errlen;
			memcached_process_error(con,
						MEMCACHED_BIN_RES_NOT_SUPPORTED,
						errstr);
			say_error((const char *)errstr, 1);
			}
		default: {
			char errstr[257];
			size_t errlen = snprintf(errstr, 256,
				"Unknown command with opcode '%.2X'",
				con->hdr->cmd
			); (void )errlen;
			memcached_process_error(con,
						MEMCACHED_BIN_RES_NOT_SUPPORTED,
						errstr);
			say_error((const char *)errstr, 1);
			}
		}
	} catch (Exception *e) {
		char errstr[257];
		size_t errlen = snprintf(errstr, 256,
			"Unsupported command '%s'",
			memcached_get_command_name(con->hdr->cmd)
		); (void )errlen;
		memcached_process_error(con, MEMCACHED_BIN_RES_SERVER_ERROR,
					e->errmsg());
		e->log();
		throw;
	}
noprocess:
	con->write_end = obuf_create_svp(&con->iobuf->out);
	con->iobuf->in.rpos += con->len;
	return 0;
}

static int
memcached_parse_request(struct memcached_connection *con) {
	struct obuf *out     = &con->iobuf->out; (void )out;
	struct ibuf *in      = &con->iobuf->in;
	const char *reqstart = in->rpos;
	/* Check that we have enough data for header */
	if (reqstart + sizeof(struct memcached_hdr) > in->wpos) {
		return sizeof(struct memcached_hdr) - (in->wpos - reqstart);
	}
	struct memcached_hdr *hdr = (struct memcached_hdr *)reqstart;
	/* error while parsing */
	if (hdr->magic != MEMCACHED_BIN_REQUEST) {
		say_error("Wrong magic, closing connection");
		return -1;
	}
	uint32_t tot_len = bswap_u32(hdr->tot_len);
	const char *reqend = reqstart + sizeof(struct memcached_hdr) + tot_len;
	/* Check that we have enough data for body */
	if (reqend > in->wpos) {
		return (reqend - in->wpos);
	}
	hdr->key_len = bswap_u16(hdr->key_len);
	hdr->tot_len = bswap_u32(hdr->tot_len);
	hdr->opaque  = bswap_u32(hdr->opaque);
	hdr->cas     = bswap_u64(hdr->cas);
	con->hdr     = hdr;
	const char *pos = reqstart + sizeof(struct memcached_hdr);
	if ((con->body.ext_len = hdr->ext_len)) {
		con->body.ext = pos;
		pos += hdr->ext_len;
	} else {
		con->body.ext = NULL;
	}
	if ((con->body.key_len = hdr->key_len)) {
		con->body.key = pos;
		pos += hdr->key_len;
	} else {
		con->body.key = NULL;
	}
	uint32_t val_len = hdr->tot_len - (hdr->ext_len + hdr->key_len);
	if ((con->body.val_len = val_len)) {
		con->body.val = pos;
		pos += val_len;
	} else {
		con->body.val = NULL;
	}
	con->len = sizeof(struct memcached_hdr) + hdr->tot_len;
	assert(pos == reqend);
	if (tot_len > 1<<20) {
		memcached_process_error(con, MEMCACHED_BIN_RES_E2BIG,
					NULL);
		say_error("Object is too big for cache");
		con->noprocess = true;
		return 0;
	}
	return 0;
}

static ssize_t
memcached_flush(struct memcached_connection *con) {
	struct ev_io *coio  = con->coio;
	struct iobuf *iobuf = con->iobuf;
	ssize_t total = coio_writev(coio, iobuf->out.iov,
				    obuf_iovcnt(&iobuf->out),
				    obuf_size(&iobuf->out));
	if (ibuf_used(&iobuf->in) == 0)
		ibuf_reset(&iobuf->in);
	obuf_reset(&iobuf->out);
	ibuf_reserve(&iobuf->in, con->cfg->readahead);
	return total;
}

static void
memcached_loop(struct memcached_connection *con)
{
	struct ev_io *coio  = con->coio;
	struct iobuf *iobuf = con->iobuf;
	int rc = 0;
	struct ibuf *in = &iobuf->in;
	size_t to_read = 1;

	for (;;) {
		ssize_t read = coio_bread(coio, in, to_read);
		if (read <= 0)
			break;
		con->cfg->stat.bytes_read += read;
		to_read = 1;
next:
		rc = memcached_parse_request(con);
		if (rc == -1) {
			/* We close connection, because of wrong magic */
			break;
		} else if (rc > 0) {
			to_read = rc;
			continue;
		}
		/**
		 * Return -1 on force connection close
		 * Return 0 if everything is parsed
		 */
		rc = memcached_process_request(con);
		if (rc < 0 || con->close_connection) {
			say_debug("Requesting exit. Exiting.");
			break;
		} else if (rc > 0) {
			to_read = rc;
			continue;
		} else if (rc == 0 && ibuf_used(in) > 0) {
			/* Need to add check for batch count */
			goto next;
		}
		/* Write back answer */
		if (!con->noreply) {
			ssize_t written = memcached_flush(con);
			con->cfg->stat.bytes_written += written;
		}
		fiber_gc();
		con->noreply = false;
		con->noprocess = false;
	}
}

static void
memcached_handler(va_list ap)
{
	struct ev_io     coio       = va_arg(ap, struct ev_io);
	struct sockaddr *addr       = va_arg(ap, struct sockaddr *);
	socklen_t        addr_len   = va_arg(ap, socklen_t);
	struct iobuf    *iobuf      = va_arg(ap, struct iobuf *);
	struct memcached_service *p = va_arg(ap, struct memcached_service *);

	struct memcached_connection con;
	/* TODO: move to connection_init */
	memset(&con, 0, sizeof(struct memcached_connection));
	con.coio      = &coio;
	con.iobuf     = iobuf;
	con.write_end = obuf_create_svp(&iobuf->out);
	con.addr      = *addr;
	con.addr_len  = addr_len;
	con.session   = session_create(con.coio->fd, *(uint64_t *)&con.addr);
	con.cfg       = p;

	/* read-write cycle */
	con.cfg->stat.curr_conns++;
	con.cfg->stat.total_conns++;
	con.cfg->stat.started = fiber_time64();
	try {
		auto scoped_guard = make_scoped_guard([&] {
			fiber_sleep(0.01);
			con.cfg->stat.curr_conns--;
			evio_close(loop(), &coio);
			iobuf_delete(iobuf);
		});

		memcached_loop(&con);
		memcached_flush(&con);
	} catch (const FiberCancelException& e) {
		throw;
	} catch (const Exception& e) {
		e.log();
	}
}

struct memcached_service*
memcached_create(const char *name, uint32_t sid)
{
	struct memcached_service *srv = (struct memcached_service *)calloc(1,
			sizeof(struct memcached_service));
	if (!srv) {
		panic("failed to allocate memory for memcached service");
		return NULL;
	}
	srv->space_id = sid;
	srv->name = name;
	return srv;
}

void
memcached_free(struct memcached_service *srv)
{
	if (srv) free(srv);
}

void
memcached_start (struct memcached_service *srv, const char *uri)
{
	srv->uri = uri;
	coio_service_init(&(srv->service), srv->name, memcached_handler, srv);
	coio_service_start((struct evio_service *)&(srv->service), srv->uri);
}

void
memcached_stop (struct memcached_service *srv)
{
	(void )srv;
	// evio_close(loop(), &(srv->service));
}

/*
void
memcached_gc ()
*/

void memcached_set_readahead (struct memcached_service *srv, int readahead)
{
	srv->readahead = readahead;
}

struct memcached_stat *memcached_get_stat (struct memcached_service *srv)
{
	return &(srv->stat);
}
