-- how to use this lib:
-- import ecs rule in your dnsdist.conf
-- dofile("/etc/dnsdist/decode_ecs.lua")
--
-- listNmg = newNMG()
-- listNmg:addMask("192.168.1.0/24")
--
-- addAction(LuaRule(ECSOptionRule(listNmg)), PoolAction("cloudflare"))

-- global variable

-- ecs rule to match specific Client Subnet defined in the 
-- listNmg variable
function ECSOptionRule(nmg)
  return function(dq)
    local options = dq:getEDNSOptions()

    if options[EDNSOptionCode.ECS] == nil then
      return false
    end

    if options[EDNSOptionCode.ECS]:count() ~= 1 then
      return false
    end

    local ecs = DecodeECS(options[EDNSOptionCode.ECS]:getValues()[1])
    if ecs == nil then
      return false
    end
    return nmg:match(ecs)
  end
end

-- this function return the client subnet as a comboAddress truncated with associated netmask
-- IPv4 and IPv6 are supported
function DecodeECS(ecs_data)
  local ip = string.byte(ecs_data:sub(2, 3))
  local netmask = string.byte(ecs_data:sub(3, 4))
  local cs_data = ecs_data:sub(5)
  local cs_table = {}

  -- decode ipv4
  if ip == 1 then
    -- padding to a size of 4
    while #cs_data < 4 do
      cs_data = cs_data .. "\0"
    end
    -- read each byte
    for i = 1, #cs_data, 1 do
      table.insert(cs_table, string.byte(cs_data:sub(i, i)) )
    end
    ca = newCA(table.concat(cs_table, "."))
    ca:truncate(netmask)
    return ca
  end

  -- decode ipv6
  if ip == 2 then
    -- padding to a size of 4
    while #cs_data < 16 do
      cs_data = cs_data .. "\0"
    end
    -- read each 2 bytes
    for i = 1, #cs_data, 2 do
      table.insert(cs_table, string.format("%02X%02X", cs_data:byte(i), cs_data:byte(i+1)) )
    end
    ca = newCA(table.concat(cs_table, ":"))
    ca:truncate(netmask)
    return ca
  end

  -- error, this should not happen
  return
end
