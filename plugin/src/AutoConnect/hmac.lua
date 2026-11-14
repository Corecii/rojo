--[[
	HMAC-SHA256 (RFC 2104) over Roblox's SHA-256, which is the only keyed
	primitive available: the engine exposes hashes but no HMAC.

	Strings are byte strings. `sha256` must return the raw 32-byte digest; it
	is injectable so the construction can be tested outside Roblox.
]]

local BLOCK_SIZE = 64

local function engineSha256(message: string): string
	return game:GetService("EncodingService"):ComputeStringHash(message, Enum.HashAlgorithm.Sha256)
end

local function xorPad(key: string, pad: number): string
	local bytes = table.create(BLOCK_SIZE)
	for i = 1, BLOCK_SIZE do
		bytes[i] = string.char(bit32.bxor(string.byte(key, i) or 0, pad))
	end
	return table.concat(bytes)
end

local hmac = {}

function hmac.toHex(bytes: string): string
	return (string.gsub(bytes, ".", function(char)
		return string.format("%02x", string.byte(char))
	end))
end

-- Returns nil if `hex` isn't an even-length hex string.
function hmac.fromHex(hex: string): string?
	if #hex % 2 ~= 0 or string.find(hex, "[^%x]") then
		return nil
	end
	return (string.gsub(hex, "%x%x", function(pair)
		return string.char(tonumber(pair, 16) :: number)
	end))
end

function hmac.sha256(key: string, message: string, sha256: ((string) -> string)?): string
	local hash = sha256 or engineSha256

	if #key > BLOCK_SIZE then
		key = hash(key)
	end

	local inner = hash(xorPad(key, 0x36) .. message)
	return hash(xorPad(key, 0x5c) .. inner)
end

return hmac
