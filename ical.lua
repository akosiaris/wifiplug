module("ical", package.seeall)

local handler = {};

function handler.VEVENT(ical, line)
	local k,v = line:match("^([%w;=/-]+):(.*)$");
	local curr_event = ical[#ical];
	if k and v then
		curr_event._last_key = k;
		curr_event[k] = v;
	elseif line:sub(1,1) == " " then
		curr_event[curr_event._last_key] = curr_event[curr_event._last_key]..line:sub(2);
		return;
	end
	
	if k == "DTSTAMP" then
		local t = {};
		t.year, t.month, t.day = v:match("^(%d%d%d%d)(%d%d)(%d%d)");
		t.hour, t.min, t.sec = v:match("T(%d%d)(%d%d)(%d%d)Z?$");
		for k,v in pairs(t) do t[k] = tonumber(v); end
		curr_event.when = os.time(t);
	end
	if k and string.find(k, '^DTSTART') then
		local t = {};
		t.year, t.month, t.day = v:match("^(%d%d%d%d)(%d%d)(%d%d)");
		t.hour, t.min, t.sec = v:match("T(%d%d)(%d%d)(%d%d)Z?$");
		for k,v in pairs(t) do t[k] = tonumber(v); end
		curr_event.start = os.time(t);
	end
	if k and string.find(k, '^DTEND') then
		local t = {};
		t.year, t.month, t.day = v:match("^(%d%d%d%d)(%d%d)(%d%d)");
		t.hour, t.min, t.sec = v:match("T(%d%d)(%d%d)(%d%d)Z?$");
		for k,v in pairs(t) do t[k] = tonumber(v); end
		curr_event.stop = os.time(t);
	end
end

function load(data)
	local ical, stack = {}, {};
	local line_num = 0;
	
	-- Parse
	local hold_buffer;
	for line in data:gmatch("(.-)[\r\n]+") do
		line_num = line_num + 1;
		if line:match("^BEGIN:") then
			local type = line:match("^BEGIN:(%S+)");
			table.insert(stack, type);
			table.insert(ical, { type = type }); 
		elseif line:match("^END:") then
			if stack[#stack] ~= line:match("^END:(%S+)") then
				return nil, "Parsing error, expected END:"..stack[#stack].." before line "..line_num;
			end
			table.remove(stack);
		elseif handler[stack[#stack]] then
			handler[stack[#stack]](ical, (hold_buffer or "")..line);
		end
	end
	
	-- Return calendar
	return ical;
end


return _M;
