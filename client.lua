config = require("client_config")
local username = config.username
local password = config.password
local datafile = config.datafile
local server = config.server
local port = config.port
-- You probably don't need to change anything under this line
timersfile = "timers.json"
json_timer = 60 --seconds
idle_timer = 30 --seconds

openssl = require("openssl")
json = require("dkjson")
require("alarm")

local socket = require("socket")
local wifiplug_common = require("wifiplug_common")
local app_id = 1
local offset = 0 -- This could be derived better, but let's play stupid for now
local version = 3

function hashpass(p)
	h = openssl.get_digest('md5')
	return string.tohex(h:digest(p)):lower()
end

function send_idle(client, session_key)
	local cmd = 'BBBB5EEEE'
	client:send(encrypt(cmd, session_key)..'\n')
end

function detect_idle(data)
	if string.match(data, '^BBBB%+OK 5') then
		return true
	end
	return false
end

function send_setstate(mac, state, session_key)
	local states = {on =  1, off =  0 }
	local cmd = "BBBB3"..","..string.gsub(mac,':',''):upper()..","..states[state]:lower().."EEEE"
	client:send(encrypt(cmd, session_key)..'\n')
end

function detect_setstate(data)
	if string.match(data, '^BBBB%+OK 3') then
		return true
	end
	return false
end

function toCSV (t)
	local s = ""
	for _,p in pairs(t) do
	s = s .. "," .. escapeCSV(p)
	end
	return string.sub(s, 2)      -- remove first comma
end
function escapeCSV (s)
	if string.find(s, '[,"]') then
	s = '"' .. string.gsub(s, '"', '""') .. '"'
	end
	return s
end

-- Login, somebody shoot me
local date = os.date("%Y%m%d%H%M%S")
cmd = 'BBBB1'..","..username..","..hashpass(password)..","..date..","..app_id..","..offset..","..version.."EEEE"
ecmd = encrypt(cmd, masterkey)

client = socket.try(socket.connect(server, port))
local try = socket.newtry(function() client:close() end)
try(client:send(ecmd..'\n'))
local answer = decrypt(client:receive('*l'), masterkey)
session_key = extract_session_key(answer)
if session_key then
	print("INFO: Logged in succesfully, session_key is: "..string.tohex(session_key))
end

-- Using alarm we will be polling the JSON file for changes json_timer X seconds
function settimers()
	local f = assert(io.open(timersfile, "r"))
	local t = f:read('*all')
	f:close()
	local obj, pos, err = json.decode(t)
	if not err then
		for i,v in pairs(obj.plugs) do
			if v.datetime == os.date("%Y-%m-%d %H:%M") then
				send_setstate(v.macaddr, v.state, session_key)
			end
		end
	else
		print("WARNING: Invalid JSON file, scheduling will not work until you fix it")
	end
	alarm(json_timer)
end

alarm(json_timer, settimers)

-- We should send an idle command json_timer now and then.
function timed_idle()
	send_idle(client, session_key)
	alarm(idle_timer)
end
alarm(idle_timer, timed_idle)

-- OMG this is so naive I wanna shoot myself in the foot. Feels like I am back to school writing simple socket programming
-- ignoring 20 years of advances in the field
while true do
	local states = {}
	states['0'] = 'OFF'
	states['1'] = 'ON'
	rd, wr, err = socket.select({client}, {}, 10)
	if not err then
		status = client:receive('*l')
		if not status then
			print("ERROR: Something serious has happened. Bailing out")
			break
		end
		status = decrypt(status, session_key)
		local obj, pos, err = json.decode(string.gsub(status, '^BBBB({.*})EEEE$', "%1"))
		if not err then
			local f = assert(io.open(datafile, 'a'))
			for i,mac in pairs(obj.macList) do
				-- This is going to be highly inefficient but with packets coming every 15-20 seconds,
				-- it does not really matter
				local t = { os.date("%Y-%m-%d %H:%M:%S"),
					 mac.MacAddr,
					 os.date("%Y-%m-%d %H:%M:%S", mac.UpdateTime/1000),
					 tostring(mac.Status),
					 states[tostring(mac.Switcher)]
					 }
				print("INFO: Got status: " .. toCSV(t))
				f:write(toCSV(t)..'\n')
			end
			f:close()
		elseif detect_setstate(status) then
			print("INFO: Detected an OK reply to a state change command")
		elseif detect_idle(status) then
			print("INFO: Detected an OK reply to a IDLE command")
		else
			print("WARNING: Unexpected message received:"..status)
		end
	end
end
client:close()
