local username = "demo"
local password = "000000"
local datafile = "data.csv"

-- You probably don't need to change anything under this line
local server = "54.217.214.117"
local port = "222"
timersfile = "timers.json"
json_timer = 60 --seconds
idle_timer = 20 --seconds

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

function idle(client, session_key)
	local cmd = 'BBBB5EEEE'
	client:send(encrypt(cmd, session_key)..'\n')
	local answer = decrypt(client:receive('*l'), session_key)
	if string.match(answer, '^BBBB%+OK 5') then
		return true
	else
		return false, answer
	end
end

function setstate(mac, state, session_key)
	local states = {on =  1, 
			ON =  1,
			On =  1,
			off =  0,
			OFF =  0,
			Off =  0,
			}
	local cmd = "BBBB3"..","..string.gsub(mac,':',''):upper()..","..states[state].."EEEE"
	print(cmd)
	client:send(encrypt(cmd, session_key)..'\n')
	local answer = decrypt(client:receive('*l'), session_key)
	if string.match(answer, '^BBBB%+OK 3') then
		return true
	else
		return false, answer
	end
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
	print("Logged in succesfully, session_key is: "..string.tohex(session_key))
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
				setstate(v.macaddr, v.state, session_key)
			end
		end
	else
		print("Invalid JSON file, fix it please")
	end
	alarm(json_timer)
end

alarm(json_timer, settimers)

-- We should send an idle command json_timer now and then.
function timed_idle()
	ret, st = idle(client, session_key)
	if ret == false then
		print("WARNING:, idle command sent and we got an answer but it was an unexpected one. Maybe we will get disconnected. Response was: "..st)
	end
	alarm(idle_timer)
end
alarm(idle_timer, timed_idle)

-- OMG this is so naive I wanna shoot myself in the foot. Feels like I am back to school writing simple socket programming
-- ignoring 20 years of advances in the field
while true do
	status = client:receive('*l')
	if not status then
		print("ERROR: Something serious has happened. Bailing out")
		break
	end
	print(status)
	status = decrypt(status, session_key)
	local obj, pos, err = json.decode(string.gsub(status, '^BBBB({.*})EEEE$', "%1"))
	if not err then
		for i,mac in pairs(obj.macList) do
			-- This is going to be highly inefficient but with packets coming every 15-20 seconds,
			-- it does not really matter
			local t = { mac.MacAddr, os.date("%Y-%m-%d %H:%M", mac.UpdateTime/1000), tostring(mac.Status) }
			print("Got status: " .. toCSV(t))
			local f = assert(io.open(datafile, 'w+'))
			f:write(toCSV(t))
			f:close()
		end
	else
		print("Unexpected message received:"..status)
	end
end
client:close()
