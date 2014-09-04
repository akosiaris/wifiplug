-- wifiplug android app protocol
require('wifiplug_common')
-- declare out protocol
wifiplug_proto = Proto('wifiplug2', 'wifiplug2 android app protocol')

function wifiplug_proto.dissector(buffer, pinfo, tree)
	pinfo.cols.protocol = 'WIFIPLUG2'
	local subtree = tree:add(wifiplug_proto, buffer(), 'Wifiplug2 Protocol Data')
	local calc_checksum = getchecksum(buffer())
	local packet_checksum = buffer(9,4)
	local cmdbyte = buffer(13,1):string():tohex()
	if calc_checksum == packet_checksum:string() then
		checksum = '(Verified)'
	else
		checksum = '(Failed)'
	end
	local data = zlib.inflate(buffer(14):string()):read('*l')
	local size = buffer(3,1):uint()
	size = size + buffer(4,1):uint() * 256
	size = size + buffer(5,1):uint() * 256 * 256
	size = size + buffer(6,1):uint() * 256 * 256 * 256

	subtree:add(buffer(), 'Data size: ' .. buffer():len()):set_generated()
	subtree:add(buffer(0,2), 'Header (constant): ' .. buffer(0,2):uint())
	subtree:add(buffer(2,1), 'Protocol Version (constant ?): ' .. buffer(2,1):uint())
	subtree:add(buffer(3,4), 'Size: ' .. size)
	subtree:add(buffer(7,1), 'Sequence Number (1/2): ' .. buffer(7,1):uint())
	subtree:add(buffer(8,1), 'Sequence Number (2/2): ' .. buffer(8,1):uint())
	subtree:add(buffer(9,4), 'Checksum: ' .. packet_checksum:string():tohex() .. checksum)
	subtree:add(buffer(13,1), 'Command Byte: ' .. string.format("%s (%s)", cmdbyte, CMDS[cmdbyte]))
	subtree:add(buffer(14), 'Compressed Data: ' .. buffer(14):string():tohex())
	local obj, pos, err = json.decode(data)
	if not err then
		data = json.encode(obj, {['indent'] = true})
	end
	subtree:add(buffer(14), 'Uncompressed Data: ' .. data):set_generated()

	-- populate_tree(plaintext, subtree, buffer)
end

-- Display all the commands - ugly... I know
CMDS = {
["00"]="ConnectRequet",
["02"]="Login",
["04"]="GetAllDeviceList",
["06"]="QueryDeviceStatus",
["08"]="ControlDevice",
["0A"]="Register",
["0C"]="AddMasterDevice",
["0E"]="AddSlaveDevice",
["10"]="DelDevice",
["12"]="ModifyDevice",
["14"]="ModifyUserInfo",
["16"]="QueryUserInfo",
["18"]="AddTimerTask",
["20"]="ModifyTimer",
["22"]="DelTimer",
["24"]="QueryTimer",
["26"]="AddNormalDevice",
["28"]="DelNormalDevice",
["2A"]="SortNormalDevice",
["2C"]="QueryNormalDevice",
["2E"]="AddScene",
["30"]="DelScene",
["32"]="ModifyScene",
["34"]="QuerySceneList",
["36"]="AddSceneDevice",
["38"]="DelSceneDevice",
["3A"]="ModifySceneDevice",
["3C"]="QuerySceneModeDevices",
["50"]="Logout",
["53"]="JumpSucc",
["54"]="ControlDevice",
["56"]="QueryDeviceStatus",
["58"]="ChangePwd",
["60"]="ForgetPwd",
["62"]="ForgetPassWithVerifySetup1",
["64"]="ForgetPassWithVerifySetup2",
["66"]="CheckUsername",
["68"]="RegisterWithVerifySetup1",
["6A"]="RegisterWithVerifySetup2",
["6C"]="ControlIRDeviceMode",
["6F"]="IRBingSetup2",
["71"]="VerifyCode",
["73"]="SetParameter",
["75"]="AddGroup",
["77"]="DelGroup",
["79"]="ModifyGroup",
["7B"]="GetAllGroupInfo",
["7D"]="AddDevice2Group",
["7F"]="DelDeviceFromGroup",
["81"]="ModifyGroupDevices",
["83"]="QueryGroupDevices",
["85"]="AddGroupTimer",
["87"]="DelGroupTimer",
["89"]="ModifyGroupTimer",
["8B"]="QueryGroupTimer",
["8D"]="ControlGroupDevice",
["8F"]="QueryListCount",
["91"]="QuerySubList",
["FC"]="IdleSucc",
["FE"]="Idle",
["01"]="ServerLoginPermit",
["03"]="ServerLoginRespond",
["05"]="ServerRespondAllDeviceList",
["07"]="ServerRespondDeviceStatus",
["09"]="ServerControlResult",
["0B"]="ServerRegisterResult",
["0D"]="ServerAddMasterDeviceResult",
["0F"]="ServerAddSlaveDeviceResult",
["11"]="ServerDelDeviceResult",
["13"]="ServerModifyDeviceResult",
["15"]="ServerModifyUserResult",
["17"]="ServerQueryUserResult",
["19"]="ServerAddTimerResult",
["21"]="ServerModifyTimerResult",
["23"]="ServerDelTimerResult",
["25"]="ServerQueryTimerResult",
["27"]="ServerAddNormalDeviceResult",
["29"]="ServerDelNormalDeviceResult",
["2B"]="ServerSortNormalDeviceResult",
["2D"]="ServerQueryNormalDevices",
["2F"]="ServerAddSceneResult",
["31"]="ServerDelSceneResult",
["33"]="ServerModifySceneResult",
["35"]="ServerQuerySceneListResult",
["37"]="ServerAddSceneDeviceResult",
["39"]="ServerDelSceneDeviceResult",
["3B"]="ServerModifySceneDeviceResult",
["3D"]="ServerQuerySceneModeDevicesResult",
["51"]="ServerLogout",
["52"]="ServerJump",
["55"]="ServerControlResult",
["57"]="ServerQueryDeviceStatus",
["59"]="ServerChangePwdResponse",
["61"]="ServerForgetPwdResponse",
["63"]="ServerReturnValidateCode",
["65"]="ServerForgetPassSucc",
["67"]="ServerCheckUsernameAvailable",
["69"]="ServerReturnValidateCode",
["6B"]="ServerRegisterSucc",
["6D"]="ServerRespIRMode",
["6E"]="ServerIRBindSetup1",
["70"]="ServerBingSucc",
["72"]="ServerVerifyCodeSucc",
["74"]="ServerSetParameterSucc",
["76"]="ServerAddGroupSucc",
["78"]="ServerDelGroupSucc",
["7A"]="ServerModifyGroupSucc",
["7C"]="ServerReturnAllGroupInfo",
["7E"]="ServerAddDevice2GroupSucc",
["80"]="ServerDelDeviceFromGroupSucc",
["82"]="ServerModifyGroupDevicesSucc",
["84"]="ServerRetrunGroupDevices",
["86"]="ServerAddGroupTimerSucc",
["88"]="ServerDelGroupTimerSucc",
["8A"]="ServerModifyGroupTImerSucc",
["8C"]="ServerReturnGroupTimer",
["8E"]="ServerControlGroupDeviceSucc",
["90"]="ServerRetrunListCount",
["92"]="ServerRetrunSubList",
["FB"]="ServerIdle",
["FD"]="ServerIdleSucc",
["FF"]="ServerException",
}
tcp_table = DissectorTable.get('tcp.port')
tcp_table:add(227, wifiplug_proto)
