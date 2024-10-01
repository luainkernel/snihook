local rcu = require("rcu")
local run
run = (require("rcu") and require("lunatik.runner")).run
local shouldstop
shouldstop = require("thread").shouldstop
local inbox
inbox = require("mailbox").inbox
local schedule, time
do
  local _obj_0 = require("linux")
  schedule, time = _obj_0.schedule, _obj_0.time
end
return function()
  local whitelist = rcu.table()
  local log = inbox(100 * 1024)
  local runtimes = {
    run("snihook/dev", true),
    run("snihook/hook", false)
  }
  for _index_0 = 1, #runtimes do
    local rt = runtimes[_index_0]
    rt:resume(whitelist, log.queue, log.event)
  end
  local previous = {
    __mode = "kv"
  }
  while not shouldstop() do
    do
      local event = log:receive()
      if event then
        local t = time() / 1000000000
        do
          local _t = previous[event]
          if _t then
            if t - _t >= 10 then
              previous[event] = nil
            end
          else
            print(event)
            previous[event] = t
          end
        end
      else
        schedule(1000)
      end
    end
  end
  local _list_0 = runtimes
  for _index_0 = 1, #_list_0 do
    local rt = _list_0[_index_0]
    rt:stop()
  end
end
