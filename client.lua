-- vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab
config = require('client_config')
local username = config.username
local password = config.password
local datafile = config.datafile
local server = config.server
local port = config.port
local gcal_url = config.gcal_url
local ical_age = config.ical_age

local username_v2 = config.username_v2
local password_v2 = config.password_v2
local datafile_v2 = config.datafile_v2
local server_v2 = config.server_v2
local port_v2 = config.port_v2

local known_macs = {}
local scheduled_macs = {}
local icaldata = nil
scheduler_timer = 60 --seconds

openssl = require('openssl')
json = require('dkjson')
https = require('ssl.https')
ical = require('ical')
require('alarm')

local socket = require('socket')
local wifiplug_common = require('wifiplug_common')
local app_id = 1
local offset = 0 -- This could be derived better, but let's play stupid for now
local version = 3

local continuation_data = ''

function fetch_ical()
    local sink
    sink, err = https.request(gcal_url)
    if not sink then
        print(err)
    end
    return sink
end

function create_rrules(event)
    if event.RRULE then
        rrules = string.split(event.RRULE, ';')
        for i, rule in pairs(rrules) do
            t = string.split(rule, '=')
            event[t[1]] = t[2]
        end
    end
    return event
end

function calculate_occurences(event)
    local SECS_PER_MONTH = { 2678400, 2419200, 2678400, 2592000, 2678400, 2592000, 2678400, 2678400, 2592000, 2678400, 2592000, 2678400 }
    local YEAR_SECS = 31536000

    -- Once every for 4 years add a day
    if (tonumber(os.date('%Y')) % 4) == 0 then
        YEAR_SECS = YEAR_SECS + 86400
        SECS_PER_MONTH[2] = SECS_PER_MONTH[2] + 86400
    end

    local DEFAULT_COUNT = 1 -- maximum number of repetitions
    local DEFAULT_INTERVAL = 1
    event.occurences = {}
    if not event.COUNT then
        event.COUNT = DEFAULT_COUNT
    end
    if not event.INTERVAL then
        event.INTERVAL = DEFAULT_INTERVAL
    end
    local months = {}
    for i=0,tonumber(event.COUNT)-1,event.INTERVAL do
        if event.FREQ == 'DAILY' then
            local diff = 86400 * i
            table.insert(event.occurences, { start = event.start + diff, stop = event.stop + diff })
        elseif event.FREQ == 'WEEKLY' then
            if event.BYDAY then
                local days = string.split(event.BYDAY, ',')
                for d=0,6,1 do
                    local diff = 604800 * i + 86400 * d
                    local day = os.date('%a', event.start + diff):upper():sub(0,2)
                    if table.contains(days, day) then
                        table.insert(event.occurences, { start = event.start + diff, stop = event.stop + diff })
                    end
                end
            end
        elseif event.FREQ == 'MONTHLY' then
            if event.BYMONTHDAY then
                local diff = 0
                local m = os.date('%m', event.start)
                for s=m,m+i-1,1 do
                    local temp = s % 12 + 1
                    diff = diff + SECS_PER_MONTH[temp]
                end
                table.insert(event.occurences, { start = event.start + diff, stop = event.stop + diff })
            end
            if event.BYDAY then
                local byday = event.BYDAY
                --print('Unimplemented')
            end
        elseif event.FREQ == 'YEARLY' then
            local diff = 31536000 * i
            table.insert(event.occurences, { start = event.start + diff , stop = event.stop + diff })
        else
            table.insert(event.occurences, { start = event.start, stop = event.stop })
        end
    end
end

function parse_event(data, start)
    data = string.gsub(data, '\\n', ';')
    data = string.gsub(data, '\\', '')
    data = string.upper(data)
    lines = string.split(data, ';')
    for i, line in pairs(lines) do
        if string.match(line, '^%x%x%x%x%x%x%x%x%x%x%x%x,O[NF]F?$') then
            t = string.split(line, ',')
            -- Store the scheduled mac_state assuming we know the MAC
            if known_macs[t[1]] then
                scheduled_macs[t[1]] = { state = t[2], start = start }
            end
        end
    end
    return nil
end

function synchronize_states()
    -- We iterate over all non-scheduled MACs
    for mac, data in pairs(known_macs) do
        if data['status'] and not scheduled_macs[mac] and data['state'] == 'OFF' then
            print('INFO: A non-scheduled MAC was found in OFF state: '.. mac .. ' Turning ON')
            send_setstate(mac, 'ON', session_key)
        end
    end
    -- Then over all scheduled MACs
    for mac, data in pairs(scheduled_macs) do
        if known_macs[mac] and known_macs[mac]['state'] ~= data['state'] and known_macs[mac]['status'] then
            if known_macs[mac]['last_change'] < data['start'] then
                print('INFO: A schedule for MAC: '..mac..' which was: ' .. known_macs[mac]['state'] .. ' to turn: '.. data['state'] ..' was found')
                send_setstate(mac, data['state'], session_key)
            else
                print('INFO: A possibly overriden by user action MAC: ' .. mac .. ' in state: ' .. known_macs[mac]['state'] .. ' scheduled for: ' .. scheduled_macs[mac]['state'] .. ' has been detected, doing nothing')
            end
        end
    end
    scheduled_macs = {}
end

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
    local states = {on =  1, off =  0, onf = 1 } -- Assume onf (a typo) means on
    local cmd = 'BBBB3'..','..string.gsub(mac,':',''):upper()..','..states[state:lower()]..'EEEE'
    client:send(encrypt(cmd, session_key)..'\n')
end

function detect_setstate(data)
    if string.match(data, '^BBBB%+OK 3') then
        return true
    end
    return false
end

function toCSV (t)
    local s = ''
    for _,p in pairs(t) do
    s = s .. ',' .. escapeCSV(p)
    end
    return string.sub(s, 2)      -- remove first comma
end
function escapeCSV (s)
    if string.find(s, '[,"]') then
    s = '"' .. string.gsub(s, '"', '""') .. '"'
    end
    return s
end

function write_status_files()
    for mac, data in pairs(known_macs) do
                local f = assert(io.open('plugstatus/'..mac..'.html', 'w'))
                local t = f:write(string.format([[
<!DOCTYPE html>
<html>
  <head>
  <title>Plug Status</title>
  <meta http-equiv="refresh" content="20">
  <style>
  .TRUE {color: green;}
  .FALSE {color: red;}
  .ON {color: green;}
  .OFF {color: red;}
  .bold { font-weight: bold; color: gray;}
  </style>
  </head>
  <body>
  <h1>
  Plug MAC: <span class="bold">%s</span>
  <!--
  | connection status: <span class="%s">%s</span>
  | plug status: <span class="%s">%s</span>
  -->
  </h1>
  <img src="%s.png" alt="%s state image">
  Note: The page is automatically updated with new data every 1 minute
  </body>
  </html>]], mac,
           tostring(data['status']):upper(), tostring(data['status']):upper(),
           data['state'], data['state'],
           tostring(data['status']):upper(), tostring(data['status']):upper()))
        f:close()
    end
end

-- Using alarm we will be polling the Google Calendar URL and submit commands every X seconds
function ical_scheduler()
    if icaldata then
        gcal_events = ical.load(icaldata['data'])
    else
        print('INFO: Google Calendar not populated yet. Please wait for first scheduler run')
        return nil
    end
    for k, event in pairs(gcal_events) do
        create_rrules(event)
        calculate_occurences(event)
    end
end

function scheduled_tasks()
    -- We should send an idle command scheduler_timer now and then.
    print('INFO: Running scheduler')
    if not icaldata then
        icaldata = { data=nil, date=0 }
    end
    local now = os.time()
    if now >= icaldata['date'] + ical_age then
        icaldata['data'] = fetch_ical()
        icaldata['date'] = os.time()
        ical_scheduler()
    end
    for k, event in pairs(gcal_events) do
        if event.type == 'VEVENT' then
            for i, oc in pairs(event.occurences) do
                if now >= oc.start and now <= oc.stop then
                    local state = parse_event(event.DESCRIPTION, oc.start)
                end
            end
        end
    end
    synchronize_states()
    send_idle(client, session_key)
    write_status_files()
    -- Scheduling toggling plugs on/off through Google cal
    alarm(scheduler_timer)
end
alarm(scheduler_timer, scheduled_tasks)
scheduled_tasks()

function detect_continuation_data(data)
    if string.match(data, 'CCC$') then
        return true
    end
    return false

end

-- Login, somebody shoot me
local date = os.date('%Y%m%d%H%M%S')
cmd = 'BBBB1'..','..username..','..hashpass(password)..','..date..','..app_id..','..offset..','..version..'EEEE'
ecmd = encrypt(cmd, masterkey)

client = socket.try(socket.connect(server, port))
local try = socket.newtry(function() client:close() end)
try(client:send(ecmd..'\n'))
local answer = decrypt(client:receive('*l'), masterkey)
session_key = extract_session_key(answer)
if session_key then
    print('INFO: Logged in succesfully, session_key is: '..string.tohex(session_key))
else
    print('ERROR: Could not login succesfully, exiting')
    os.exit(1)
end

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
            print('ERROR: Something serious has happened. Bailing out')
            break
        end
        status = decrypt(status, session_key)
        if detect_continuation_data(status) then
            continuation_data = continuation_data .. string.gsub(status,'^BBBB(.*)CCC$', '%1')
        elseif continuation_data ~= '' then
            status = continuation_data .. string.gsub(status, '^BBBB', '')
            continuation_data = ''
        end
        if continuation_data == '' then
            local obj, pos, err = json.decode(string.gsub(status, '^BBBB({.*})EEEE$', '%1'))
            if not err then
                local now = os.date('%Y-%m-%d %H:%M:%S')
                local f = assert(io.open(datafile, 'a'))
                for i,mac in pairs(obj.macList) do
                    -- This is going to be highly inefficient but with packets coming every 15-20 seconds,
                    -- it does not really matter
                    local t = { now,
                         mac.MacAddr,
                         os.date('%Y-%m-%d %H:%M:%S', mac.UpdateTime/1000),
                         tostring(mac.Status),
                         states[tostring(mac.Switcher)]
                         }
                    print('INFO: Got status: ' .. toCSV(t))
                    f:write(toCSV(t)..'\n')
                    known_macs[mac.MacAddr] = {
                        state = states[tostring(mac.Switcher)],
                        last_change = mac.UpdateTime/1000,
                        status = mac.Status
                        }
                end
                f:close()
            elseif detect_setstate(status) then
                print('INFO: Detected an OK reply to a state change command')
            elseif detect_idle(status) then
                print('INFO: Detected an OK reply to a IDLE command')
            else
                print('WARNING: Unexpected message received:'..status)
            end
        end
    end
end
client:close()
