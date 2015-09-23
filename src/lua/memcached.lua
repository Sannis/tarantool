-- memcached.lua

local ffi = require('ffi')

ffi.cdef[[
typedef double time_t;

struct memcached_stat {
    /* connection informations */
    unsigned int  curr_items;
    unsigned int  total_items;
    unsigned int  curr_conns;
    unsigned int  total_conns;
    uint64_t      bytes_read;
    uint64_t      bytes_written;
    /* time when process was started */
    time_t        started;
    /* get statistics */
    uint64_t      cmd_get;
    uint64_t      get_hits;
    uint64_t      get_misses;
    /* delete stats */
    uint64_t      cmd_delete;
    uint64_t      delete_hits;
    uint64_t      delete_misses;
    /* set statistics */
    uint64_t      cmd_set;
    uint64_t      cas_hits;
    uint64_t      cas_badval;
    uint64_t      cas_misses;
    /* incr/decr stats */
    uint64_t      cmd_incr;
    uint64_t      incr_hits;
    uint64_t      incr_misses;
    uint64_t      cmd_decr;
    uint64_t      decr_hits;
    uint64_t      decr_misses;
    /* touch/flush stats */
    uint64_t      cmd_touch;
    uint64_t      touch_hits;
    uint64_t      touch_misses;
    uint64_t      cmd_flush;
    /* expiration stats */
    uint64_t      evictions;
    uint64_t      reclaimed;
    /* authentication stats */
    uint64_t      auth_cmds;
    uint64_t      auth_errors;
};

void              memcached_set_readahead (struct memcached_service *, int);
struct memcached_stat *memcached_get_stat (struct memcached_service *);

struct memcached_service *memcached_create(const char *, uint32_t);
void memcached_start (struct memcached_service *, const char *);
void memcached_stop  (struct memcached_service *);
void memcached_free  (struct memcached_service *);
]]

local memcached_services = {}

local RUNNING = 'r'
local STOPPED = 's'
local ERRORED = 'e'

local memcached_mt = {
    cfg = function (self, opts)
        opts = opts or {}
        if type(opts) ~= 'table' then
            error('arguments must be in dictionary')
        end
        opts.readahead = opts.readahead or box.cfg.readahead
        if type(opts.readahead) ~= 'number' and opts.readahead > 16320 then
            error("bad 'readahead' value")
        end
        ffi.C.memcached_set_readahead(self.service, opts.readahead)
    end,
    start = function (self)
        if self.status == RUNNING then
            error("memcached '%s' is already started", self.name)
        end
        box.error.clear()
        require('log').info(self.uri)
        ffi.C.memcached_start(self.service, self.uri)
        if box.error.last() ~= nil then
            error("error while binding on port")
        end
        self.status = RUNNING
    end,
    stop = function (self)
        if self.status == STOPPED then
            error("memcached '%s' is already stopped", self.name)
        end
        box.error.clear()
        local rc = ffi.C.memcached_stop(self.service)
        if box.error.last() ~= nil then
            error('error while stopping memcached')
        end
        self.status = STOPPED
    end,
    info = function (self)
        stats = ffi.C.memcached_get_stat(self.service)
        return {
            total_items = stats[0].total_items;
            curr_conns = stats[0].curr_conns;
            total_conns = stats[0].total_conns;
            bytes_read = stats[0].bytes_read;
            bytes_written = stats[0].bytes_written;
            started = stats[0].started;
            cmd_get = stats[0].cmd_get;
            get_hits = stats[0].get_hits;
            get_misses = stats[0].get_misses;
            cmd_delete = stats[0].cmd_delete;
            delete_hits = stats[0].delete_hits;
            delete_misses = stats[0].delete_misses;
            cmd_set = stats[0].cmd_set;
            cas_hits = stats[0].cas_hits;
            cas_badval = stats[0].cas_badval;
            cas_misses = stats[0].cas_misses;
            cmd_incr = stats[0].cmd_incr;
            incr_hits = stats[0].incr_hits;
            incr_misses = stats[0].incr_misses;
            cmd_decr = stats[0].cmd_decr;
            decr_hits = stats[0].decr_hits;
            decr_misses = stats[0].decr_misses;
            cmd_touch = stats[0].cmd_touch;
            touch_hits = stats[0].touch_hits;
            touch_misses = stats[0].touch_misses;
            cmd_flush = stats[0].cmd_flush;
            evictions = stats[0].evictions;
            reclaimed = stats[0].reclaimed;
            auth_cmds = stats[0].auth_cmds;
            auth_errors = stats[0].auth_errors;
            curr_items = stats[0].curr_items;
        }
    end
}

local function memcached_init(opts)
    local conf = {}
    conf.uri = opts.uri or '0.0.0.0:11211'
    conf.configured = false
    conf.space = box.schema.create_space(opts.name)
    conf.space:create_index('primary', { parts = {1, 'str'} })
    box.schema.user.grant('guest', 'read,write', 'space', opts.name)
    conf.opts    = opts
    conf.service = ffi.C.memcached_create(opts.name, conf.space.id)
    if conf.service == nil then
        error("can't allocate memory")
    end
    conf.service = ffi.gc(conf.service, ffi.C.memcached_free)
    memcached_services[opts.name] = setmetatable(conf,
        { __index = memcached_mt }
    )
    conf:cfg{opts}
    conf:start()
    return conf
end

return {
    create = memcached_init;
    get    = function (name) return memcached_services[name] end;
    debug  = memcached_services;
}
