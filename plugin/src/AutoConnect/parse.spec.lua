return function()
	local HttpService = game:GetService("HttpService")

	local AutoConnect = require(script.Parent)
	local hmac = require(script.Parent.hmac)

	local key = "test key"

	local function signed(payload: string, signingKey: string?): string
		return HttpService:JSONEncode({
			payload = payload,
			signature = hmac.toHex(hmac.sha256(signingKey or key, payload)),
		})
	end

	it("should accept a correctly signed request and apply defaults", function()
		local request, reason = AutoConnect.parse(signed('{"version":1,"port":35000,"projectName":"game-1"}'), key)
		expect(reason).to.equal(nil)
		assert(request, "expected a request")
		expect(request.host).to.equal("localhost")
		expect(request.port).to.equal("35000")
		expect(request.projectName).to.equal("game-1")
		expect(request.reconnect).to.equal(false)
	end)

	it("should read host and reconnect", function()
		local request = AutoConnect.parse(
			signed('{"version":1,"port":1,"projectName":"p","host":"127.0.0.1","reconnect":true}'),
			key
		)
		assert(request, "expected a request")
		expect(request.host).to.equal("127.0.0.1")
		expect(request.reconnect).to.equal(true)
	end)

	it("should accept an upper-case signature", function()
		local payload = '{"version":1,"port":1,"projectName":"p"}'
		local raw = HttpService:JSONEncode({
			payload = payload,
			signature = string.upper(hmac.toHex(hmac.sha256(key, payload))),
		})
		expect(AutoConnect.parse(raw, key)).to.be.ok()
	end)

	it("should reject a value signed with another key", function()
		local request, reason = AutoConnect.parse(signed('{"version":1,"port":1,"projectName":"p"}', "other"), key)
		expect(request).to.equal(nil)
		expect(reason).to.be.ok()
	end)

	it("should reject a payload changed after signing", function()
		local raw = signed('{"version":1,"port":1,"projectName":"p"}')
		raw = string.gsub(raw, '\\"port\\":1', '\\"port\\":2')
		expect(AutoConnect.parse(raw, key)).to.equal(nil)
	end)

	it("should reject malformed values", function()
		expect(AutoConnect.parse("not json", key)).to.equal(nil)
		expect(AutoConnect.parse('{"payload":1,"signature":"00"}', key)).to.equal(nil)
		expect(AutoConnect.parse(signed("not json"), key)).to.equal(nil)
		expect(AutoConnect.parse(signed('{"version":2,"port":1,"projectName":"p"}'), key)).to.equal(nil)
		expect(AutoConnect.parse(signed('{"version":1,"port":0,"projectName":"p"}'), key)).to.equal(nil)
		expect(AutoConnect.parse(signed('{"version":1,"port":1.5,"projectName":"p"}'), key)).to.equal(nil)
		expect(AutoConnect.parse(signed('{"version":1,"port":1,"projectName":""}'), key)).to.equal(nil)
		expect(AutoConnect.parse(signed('{"version":1,"port":1,"projectName":"p","reconnect":"yes"}'), key)).to.equal(
			nil
		)
	end)

	it("should be off without a key module", function()
		local root = Instance.new("Folder")
		expect(AutoConnect.readKey(root)).to.equal(nil)

		local notAModule = Instance.new("Folder")
		notAModule.Name = "AutoConnectKey"
		notAModule.Parent = root
		expect(AutoConnect.readKey(root)).to.equal(nil)

		root:Destroy()
	end)
end
