local rcu = require("rcu")
local run
run = (rcu and require("lunatik.runner")).run
local shouldstop
shouldstop = require("thread").shouldstop
local schedule
schedule = require("linux").schedule
return function()
  local whitelist = rcu.table()
  local runtimes = {
    run("snihook/dev", true),
    run("snihook/hook", false)
  }
  for _index_0 = 1, #runtimes do
    local rt = runtimes[_index_0]
    rt:resume(whitelist)
  end
  while not shouldstop() do
    schedule(1000)
  end
  local _list_0 = runtimes
  for _index_0 = 1, #_list_0 do
    local rt = _list_0[_index_0]
    rt:stop()
  end
end
