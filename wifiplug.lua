-- wifiplug android app protocol
openssl = require("openssl")
json = require("dkjson")
sessionkey = ''
des3ecb = openssl.get_cipher('des-ede3')
-- declare out protocol
wifiplug_proto = Proto("wifiplug", "wifiplug android app protocol")
-- Yes this is the master 3DES key used to authenticate users and negotiate 3DES session keys. Secure heh ?
wifiplug_proto.prefs.masterkey = Pref.string('masterkey', '""OX'..string.char(0x88)..'8(%%yQ'..string.char(0xcb)..'0@6(3)'..string.char(0x11)..'KD'..string.char(0xfe)..'vh', 'Wifiplugs master key')
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
	if last > 0 and last <= 8 then
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

	local key
	local plaintext
	if sessionkey ~= ''  then
		key = sessionkey
	else
		key = wifiplug_proto.prefs.masterkey
	end

	-- First let's try with a possible key
	plaintext = decrypt(buffer():string(), key)
	-- Trying to decrypt the first packets in a conversation? Fallback to masterkey
	if not detect_correct_decryption(plaintext) then
		plaintext = decrypt(buffer():string(), wifiplug_proto.prefs.masterkey)
	end
	local sk = extract_session_key(plaintext)
	if sk ~= nil then
		sessionkey = sk
	end
	populate_tree(plaintext, subtree, buffer)
end

function detect_correct_decryption(s)
	if string.match(s, '^B+') then
		return true
	end
	return false
end

function extract_session_key(s)
	if string.match(s, '^BBBB%+OK 1') then
		local parts = split(s, " ")
		k = parts[#parts]
		k = string.gsub(k, 'E+$', '')
		k = string.fromhex(k)
		return k
	else
		return nil
	end
end

function canonicalize_mac(mac)
	-- ugly ugly, either lua is crappy or my knowledge of it that bad (probably the latter)
	return string.gsub(mac,
	'([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])([0-9A-F][0-9A-F])',
	'%1:%2:%3:%4:%5:%6')

end

-- Populate tree
function populate_tree(s, t, b)
-- Let's see if it is json first
	local obj, pos, err = json.decode(string.gsub(s, '^BBBB({.*})EEEE$', "%1"))
	if not err then
		maclist = t:add(b(), 'MAC list')
		for i,mac in pairs(obj.macList) do
			mact = maclist:add(b(), 'MAC')
			mact:add(b(), 'Id: '             ..mac.Id)
			mact:add(b(), 'Mac Address: '        ..canonicalize_mac(mac.MacAddr)):set_generated()
			mact:add(b(), 'Major Type: '      ..mac.MajorType)
			mact:add(b(), 'Minor Type: '      ..mac.MinorType)
			mact:add(b(), 'Name: '           ..mac.Name)
			mact:add(b(), 'Remark: '         ..mac.Remark)
			mact:add(b(), 'Status: '         ..tostring(mac.Status))
			mact:add(b(), 'Switcher: '       ..mac.Switcher)
			mact:add(b(), 'Switcher Count: '  ..mac.SwitcherCount)
			mact:add(b(), 'Switcher Name: '   ..mac.SwitcherName)
			mact:add(b(), 'Switcher Value1: ' ..mac.SwitcherValue1)
			mact:add(b(), 'Switcher Value2: ' ..mac.SwitcherValue2)
			mact:add(b(), 'Switcher Value3: ' ..mac.SwitcherValue3)
			mact:add(b(), 'Switcher Value4: ' ..mac.SwitcherValue4)
			mact:add(b(), 'Switcher Value5: ' ..mac.SwitcherValue5)
			mact:add(b(), 'Update Time: '     ..os.date("%Y-%m-%d %H:%M", mac.UpdateTime)):set_generated()
		end
		timerlist = t:add(b(), 'Timer list')
		for i,timer in pairs(obj.timerList) do
			timert = timerlist:add(b(), 'Timer')
			timert:add(b(), 'Id: '         ..timer.Id)
			timert:add(b(), 'MAC Id: '      ..timer.MacId)
			timert:add(b(), 'One Switcher:'..timer.OneSwitcher)
			timert:add(b(), 'Remark: '     ..timer.Remark)
			timert:add(b(), 'Switcher Num:'..timer.SwitcherNum)
			timert:add(b(), 'Timer: '      ..timer.Timer)
			timert:add(b(), 'Timer Type: '  ..timer.TimerType)
		end
	else
		local parts = split(s, ",")
		for i,v in pairs(parts) do
			v = string.gsub(v, 'E+$', '')
			st = t:add(b(), 'Unidentified yet data'..v)
			detect(i, v, st, b)
		end
	end
end

-- Detect parts of the packet
-- I have not written such ugly code in a long time
function detect(i, v, subtree, b)
	if v == 'BBBB1' then
		subtree:set_generated()
		subtree:set_text('Command: Login')
	elseif string.match(v, '^BBBB5') then
		subtree:set_generated()
		subtree:set_text('Command: Idle (maybe?): ' .. v)
	elseif string.match(v, '^BBBB%+OK 1') then
		subtree:set_generated()
		subtree:set_text('Response: successful Login: ' .. v)
	elseif string.match(v, '^BBBB%+OK 5') then
		subtree:set_generated()
		subtree:set_text('Response: Idle OK (maybe?): ' .. v)
	elseif i == 2 then
		subtree:set_text("Username: " .. v)
	elseif i == 3 then
		subtree:set_text("Password(MD5): " .. v)
	elseif i == 4 then
		subtree:set_text("Date: " .. v)
	elseif i == 5 then
		subtree:set_text("App_ID: " .. v)
	elseif i == 6 then
		subtree:set_text("Timezone Offset?: " .. v)
	elseif i == 7 then
		subtree:set_text("Version: " .. v)
	end
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(222, wifiplug_proto)
