-- wifiplug android app protocol
require('wifiplug_common')
-- declare out protocol
wifiplug_proto = Proto("wifiplug2", "wifiplug2 android app protocol")
function wifiplug_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = "WIFIPLUG2"
	local subtree = tree:add(wifiplug_proto, buffer(), "Wifiplug2 Protocol Data")
	local calc_checksum = getchecksum(buffer())
	local packet_checksum = buffer(9,4)
	if calc_checksum == packet_checksum:string() then
		checksum = '(Verified)'
	else
		checksum = '(Failed)'
	end
	local data = zlib.inflate(buffer(14):string()):read('*l')

	subtree:add(buffer(), "Data size: " .. buffer():len()):set_generated()
	subtree:add(buffer(0,2), "Header (constant): " .. buffer(0,2):uint())
	subtree:add(buffer(2,1), "Protocol Version (constant ?): " .. buffer(2,1):uint())
	subtree:add(buffer(3,1), "Size: " .. buffer(3,1):uint())
	subtree:add(buffer(4,3), "Size (wtf?): " .. buffer(4,3):uint())
	subtree:add(buffer(7,1), "Sequence Number (1/2): " .. buffer(7,1):uint())
	subtree:add(buffer(8,1), "Sequence Number (2/2): " .. buffer(8,1):uint())
	subtree:add(buffer(9,4), "Checksum: " .. packet_checksum:string():tohex() .. checksum)
	subtree:add(buffer(13,1), "Command Byte: " .. buffer(13,1):string():tohex())
	subtree:add(buffer(14), "Compressed Data: " .. buffer(14):string():tohex())
	subtree:add(buffer(14), "Uncompress Data: " .. data):set_generated()

	-- populate_tree(plaintext, subtree, buffer)
end

tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(227, wifiplug_proto)
