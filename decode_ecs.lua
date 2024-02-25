-- how to use this lib:
-- import ecs rule in your dnsdist.conf
-- dofile("/etc/dnsdist/decode_ecs.lua")
-- addAction(LuaRule(ECSOptionRule), PoolAction("cloudflare"))

-- global variable
listNmg = newNMG()
listNmg:addMask("192.168.1.0/24")

-- ecs rule to match specific Client Subnet defined in the 
-- listNmg variable
function ECSOptionRule(dq)
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
  return listNmg:match(ecs)
end
