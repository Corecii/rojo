return function()
	local hmac = require(script.Parent.hmac)

	local function hexMac(key: string, message: string): string
		return hmac.toHex(hmac.sha256(key, message))
	end

	-- RFC 4231 test cases 1-4, 6 and 7 (5 tests truncation, which isn't used)
	it("should match RFC 4231 test case 1", function()
		expect(hexMac(string.rep("\x0b", 20), "Hi There")).to.equal(
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
		)
	end)

	it("should match RFC 4231 test case 2", function()
		expect(hexMac("Jefe", "what do ya want for nothing?")).to.equal(
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
		)
	end)

	it("should match RFC 4231 test case 3", function()
		expect(hexMac(string.rep("\xaa", 20), string.rep("\xdd", 50))).to.equal(
			"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
		)
	end)

	it("should match RFC 4231 test case 4", function()
		local key = hmac.fromHex("0102030405060708090a0b0c0d0e0f10111213141516171819") :: string
		expect(hexMac(key, string.rep("\xcd", 50))).to.equal(
			"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
		)
	end)

	it("should match RFC 4231 test case 6 (key longer than a block)", function()
		expect(hexMac(string.rep("\xaa", 131), "Test Using Larger Than Block-Size Key - Hash Key First")).to.equal(
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
		)
	end)

	it("should match RFC 4231 test case 7 (key and data longer than a block)", function()
		local message = "This is a test using a larger than block-size key and a larger than block-size data."
			.. " The key needs to be hashed before being used by the HMAC algorithm."
		expect(hexMac(string.rep("\xaa", 131), message)).to.equal(
			"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
		)
	end)

	it("should round-trip hex", function()
		expect(hmac.fromHex("00ff10")).to.equal("\x00\xff\x10")
		expect(hmac.toHex("\x00\xff\x10")).to.equal("00ff10")
		expect(hmac.fromHex("0")).to.equal(nil)
		expect(hmac.fromHex("zz")).to.equal(nil)
	end)
end
