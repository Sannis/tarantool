
-- write data recover from logs only

name = string.match(arg[0], "([^,]+)%.lua")
os.execute("rm -f " .. name .."/*.snap")
os.execute("rm -f " .. name .."/*.xlog")

--# stop server default
--# start server default

name = string.match(arg[0], "([^,]+)%.lua")
os.execute("touch " .. name .."/lock")

space = box.schema.space.create('test', { engine = 'sophia' })
index = space:create_index('primary')
for key = 1, 1000 do space:insert({key}) end

--# stop server default
--# start server default

name = string.match(arg[0], "([^,]+)%.lua")
os.execute("rm -f " .. name .."/lock")

space = box.space['test']
index = space.index['primary']
index:select({}, {iterator = box.index.ALL})
space:drop()
