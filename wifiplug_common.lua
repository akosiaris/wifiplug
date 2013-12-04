openssl = require('openssl')
json = require('dkjson')
sessionkey = ''
des3ecb = openssl.get_cipher('des-ede3')
-- declare out protocol
-- Yes this is the master 3DES key used to authenticate users and negotiate 3DES session keys. Secure heh ?
masterkey = '""OX'..string.char(0x88)..'8(%%yQ'..string.char(0xcb)..'0@6(3)'..string.char(0x11)..'KD'..string.char(0xfe)..'vh'
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

function string.tohex(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

function decrypt(c, k)
    iv = ''
    local c1 = des3ecb:init(false, k, iv)
    local p = c1:update(string.fromhex(c))
    local final = c1:final()
    if final then
        p = p..final
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

function encrypt(p, k)
    iv = ''
    local c1 = des3ecb:init(true, k, iv)
    local c = c1:update(p)
    local final = c1:final()
    if final then
        c = c..final
    end
    return string.tohex(c)
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
