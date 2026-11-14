--[[
	Signed auto-connect: a place can ask the plugin to connect to a server by
	holding a value signed with a key installed in the plugin. Without the key
	the feature is off.

	The key is a ModuleScript named `AutoConnectKey` at the plugin's root that
	returns a hex string. Tools that install the plugin add it; release builds
	of Rojo don't ship one.

	The trigger is a StringValue named `RojoAutoConnect` directly under `game`,
	or else a string attribute `RojoAutoConnect` on Workspace. Its value is JSON:

		{"payload": "<payload JSON>", "signature": "<hex HMAC-SHA256(key, payload)>"}

	The signature covers the payload string exactly as written. The payload:

		{"version": 1, "port": 34872, "host": "localhost", "projectName": "...", "reconnect": true}

	`host` defaults to localhost and `reconnect` to false. The plugin only
	syncs if the server's project name equals `projectName`.
]]

local HttpService = game:GetService("HttpService")

local hmac = require(script.hmac)

local TRIGGER_NAME = "RojoAutoConnect"
local KEY_MODULE_NAME = "AutoConnectKey"

export type Request = {
	host: string,
	port: string,
	projectName: string,
	reconnect: boolean,
}

local AutoConnect = {}

-- Returns the raw key bytes, or nil if the plugin has no (valid) key.
function AutoConnect.readKey(pluginRoot: Instance): (string?, string?)
	local module = pluginRoot:FindFirstChild(KEY_MODULE_NAME)
	if module == nil or not module:IsA("ModuleScript") then
		return nil, nil
	end

	local ok, hex = pcall(require, module)
	if not ok or typeof(hex) ~= "string" then
		return nil, `{KEY_MODULE_NAME} must return a hex string`
	end

	local key = hmac.fromHex(hex)
	if key == nil or #key == 0 then
		return nil, `{KEY_MODULE_NAME} must return a hex string`
	end

	return key, nil
end

-- Verifies and parses a trigger value. Returns the request, or nil and a
-- reason.
function AutoConnect.parse(raw: string, key: string): (Request?, string?)
	local ok, outer = pcall(HttpService.JSONDecode, HttpService, raw)
	if not ok or typeof(outer) ~= "table" then
		return nil, "it isn't JSON"
	end

	local payload, signature = outer.payload, outer.signature
	if typeof(payload) ~= "string" or typeof(signature) ~= "string" then
		return nil, "it needs string fields 'payload' and 'signature'"
	end

	if string.lower(signature) ~= hmac.toHex(hmac.sha256(key, payload)) then
		return nil, "its signature doesn't match this plugin's key"
	end

	local decoded
	ok, decoded = pcall(HttpService.JSONDecode, HttpService, payload)
	if not ok or typeof(decoded) ~= "table" then
		return nil, "its payload isn't JSON"
	end

	if decoded.version ~= 1 then
		return nil, `payload version {tostring(decoded.version)} isn't supported`
	end

	local port = decoded.port
	if typeof(port) ~= "number" or port ~= math.floor(port) or port < 1 or port > 65535 then
		return nil, "payload 'port' must be a whole number from 1 to 65535"
	end

	if typeof(decoded.projectName) ~= "string" or decoded.projectName == "" then
		return nil, "payload 'projectName' must be a non-empty string"
	end

	if decoded.host ~= nil and (typeof(decoded.host) ~= "string" or decoded.host == "") then
		return nil, "payload 'host' must be a non-empty string"
	end

	if decoded.reconnect ~= nil and typeof(decoded.reconnect) ~= "boolean" then
		return nil, "payload 'reconnect' must be a boolean"
	end

	return {
		host = decoded.host or "localhost",
		port = tostring(port),
		projectName = decoded.projectName,
		reconnect = decoded.reconnect == true,
	},
		nil
end

local function currentTrigger(): string?
	local value = game:FindFirstChild(TRIGGER_NAME)
	if value ~= nil and value:IsA("StringValue") then
		return value.Value
	end

	local attribute = workspace:GetAttribute(TRIGGER_NAME)
	if typeof(attribute) == "string" then
		return attribute
	end

	return nil
end

-- Calls `onChanged` with the trigger value now if there is one, then whenever
-- it changes (nil when it's removed). Returns a function that stops watching.
function AutoConnect.watch(onChanged: (string?) -> ()): () -> ()
	local connections = {}
	local valueConnection: RBXScriptConnection? = nil
	local last: string? = nil
	local stopped = false

	local function update()
		if stopped then
			return
		end

		if valueConnection ~= nil then
			valueConnection:Disconnect()
			valueConnection = nil
		end

		local value = game:FindFirstChild(TRIGGER_NAME)
		if value ~= nil and value:IsA("StringValue") then
			valueConnection = value.Changed:Connect(update)
		end

		local current = currentTrigger()
		if current ~= last then
			last = current
			onChanged(current)
		end
	end

	local function onChild(child: Instance)
		if child.Name == TRIGGER_NAME then
			-- Defer so a value created and then filled in reads as filled in.
			task.defer(update)
		end
	end

	table.insert(connections, game.ChildAdded:Connect(onChild))
	table.insert(connections, game.ChildRemoved:Connect(onChild))
	table.insert(connections, workspace:GetAttributeChangedSignal(TRIGGER_NAME):Connect(update))

	update()

	return function()
		stopped = true
		for _, connection in connections do
			connection:Disconnect()
		end
		if valueConnection ~= nil then
			valueConnection:Disconnect()
		end
	end
end

return AutoConnect
