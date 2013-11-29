-- wifiplug android app protocol
require("openssl")
-- Yes this is the master 3DES key used to authenticate users and negotiate 3DES session keys. Secure heh ?
key='""OX'..string.char(0x88)..'8(%%yQ'..string.char(0xcb)..'0@6(3)'..string.char(0x11)..'KD'..string.char(0xfe)..'vh'
des3ecb = openssl.get_cipher('des-ede3')
-- declare out protocol
wifiplug_proto = Proto("wifiplug", "wifiplug android app protocol")
-- helper functions
-- Compatibility: Lua-5.1
function split(str, pat)
   local t = {}  -- NOTE: use {n = 0} in Lua-5.0
   local fpat = "(.-)" .. pat
   local last_end = 1
   local s, e, cap = str:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
	 table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
   end
   if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
   end
   return t
end

function string.fromhex(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end

function decrypt(c, k)
	iv = ''
	local c1 = des3ecb:init(false, k, iv)
	local p = c1:update(string.fromhex(c))
	local final = c1:final()
	if final then
		p = plaintext..final
	end
	-- Remove possible padding
	last = string.match(p, '.$')
	last = string.byte(last)
	if last > 0 and last < 8 then
		local pattern = ''
		for i=1,last do
			pattern = pattern..string.char(last)
		end
		p = string.gsub(p, pattern..'$', '')
	end
	return p
end


function wifiplug_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "WIFIPLUG"
	local subtree = tree:add(wifiplug_proto, buffer(), "Wifiplug Protocol Data")
	local plaintext = decrypt(buffer():string(), key)
	print(buffer():string())
	print(plaintext)
	local parts = split(plaintext, ",")
	for i,v in pairs(parts) do
		v = string.gsub(v, 'E+$', '')
		subtree:add(buffer(), detect(i, v))
	end
end

-- Detect parts of the packet
function detect(i, v)
	if v == 'BBBB1' then
		return "Command: Login"
	elseif i == 2 then
		return "Username: " .. v
	elseif i == 3 then
		return "Password(MD5): " .. v
	elseif i == 4 then
		return "Date: " .. v
	elseif i == 5 then
		return "App_ID: " .. v
	elseif i == 6 then
		return "Timezone Offset?: " .. v
	elseif i == 7 then
		return "Version: " .. v
	else
		return "DATA: " .. v
	end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(222, wifiplug_proto)
