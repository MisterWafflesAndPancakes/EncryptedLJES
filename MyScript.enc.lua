-- Self-decrypting encrypted script
-- Randomised AES key fragments
local fragments = {
        {t="hex", d="18"},
        {t="hex", d="8d76"},
        {t="hexchars", d={"c","2","3","7","7","1"}},
        {t="bytes", d={71,217,109}},
        {t="hex", d="22f995df"},
        {t="hex", d="7b8d5b52"},
        {t="hex", d="42"},
        {t="hexchars", d={"0","9","4","3"}},
        {t="hex", d="2f"},
        {t="hex", d="86fa"},
        {t="hexchars", d={"a","4"}},
        {t="hexchars", d={"7","9","c","d"}},
        {t="hex", d="93c3"},
        {t="hex", d="239e3fa1"}
}

-- Helpers to rebuild a hex key from mixed fragments
local function b64decode(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = data:gsub('[^'..b..'=]', '')
    local t, m, a = {}, 0, 0
    for i = 1, #data do
        local c = data:sub(i,i)
        if c ~= '=' then
            local idx = b:find(c, 1, true)
            if not idx then break end
            a = bit32.bor(bit32.lshift(a, 6), (idx - 1))
            m = m + 6
            if m >= 8 then
                m = m - 8
                local byte = bit32.band(bit32.rshift(a, m), 0xFF)
                t[#t+1] = string.char(byte)
                a = bit32.band(a, (bit32.lshift(1, m) - 1))
            end
        end
    end
    return table.concat(t)
end

local function byte_to_hex(n)
    return string.format("%02x", bit32.band(n or 0, 0xFF))
end

local function bytes_to_hex(str)
    local out = {}
    for i = 1, #str do
        out[#out+1] = string.format("%02x", str:byte(i))
    end
    return table.concat(out)
end

local function rebuildKeyHex()
    local acc = {}
    for i = 1, #fragments do
        local f = fragments[i]
        if f.t == "hex" then
            acc[#acc+1] = f.d
        elseif f.t == "hexchars" then
            acc[#acc+1] = table.concat(f.d)
        elseif f.t == "bytes" then
            local tmp = {}
            for j = 1, #f.d do
                tmp[#tmp+1] = byte_to_hex(f.d[j])
            end
            acc[#acc+1] = table.concat(tmp)
        elseif f.t == "b64" then
            acc[#acc+1] = bytes_to_hex(b64decode(f.d))
        else
            acc[#acc+1] = tostring(f.d)
        end
    end
    local hex = table.concat(acc)
    assert(#hex == 64, "Rebuilt AES key must be 64 hex chars, got "..#hex)
    return hex
end

local AES_KEY_HEX = rebuildKeyHex()

-- Disguised iv fragments
local iv_fragments = {
        {t="hex", d="0a76ca87"},
        {t="hex", d="fc"},
        {t="hex", d="a3"},
        {t="hex", d="66c9d9"},
        {t="hexchars", d={"4","9","9","5","f","7"}},
        {t="hexchars", d={"c","f","6","8","f","e"}},
        {t="bytes", d={201}}
}

local function rebuild_iv_hex()
    local acc = {}
    for i = 1, #iv_fragments do
        local f = iv_fragments[i]
        if f.t == "hex" then
            acc[#acc+1] = f.d
        elseif f.t == "hexchars" then
            acc[#acc+1] = table.concat(f.d)
        elseif f.t == "bytes" then
            local tmp = {}
            for j = 1, #f.d do
                tmp[#tmp+1] = byte_to_hex(f.d[j])
            end
            acc[#acc+1] = table.concat(tmp)
        elseif f.t == "b64" then
            acc[#acc+1] = bytes_to_hex(b64decode(f.d))
        else
            acc[#acc+1] = tostring(f.d)
        end
    end
    return table.concat(acc)
end

local IV_HEX = rebuild_iv_hex()

-- Disguised cipher fragments
local cipher_fragments = {
        {t="b64", d="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"}
}

local function rebuild_cipher_hex()
    local acc = {}
    for i = 1, #cipher_fragments do
        local f = cipher_fragments[i]
        if f.t == "hex" then
            acc[#acc+1] = f.d
        elseif f.t == "hexchars" then
            acc[#acc+1] = table.concat(f.d)
        elseif f.t == "bytes" then
            local tmp = {}
            for j = 1, #f.d do
                tmp[#tmp+1] = byte_to_hex(f.d[j])
            end
            acc[#acc+1] = table.concat(tmp)
        elseif f.t == "b64" then
            acc[#acc+1] = bytes_to_hex(b64decode(f.d))
        else
            acc[#acc+1] = tostring(f.d)
        end
    end
    return table.concat(acc)
end

local CIPHER_HEX = rebuild_cipher_hex()

-- Sanity checks
assert(#AES_KEY_HEX == 64, "Bad key length: "..#AES_KEY_HEX)
assert(#IV_HEX == 32, "IV hex must be 32 chars")
assert(#CIPHER_HEX % 32 == 0, "Cipher hex length must be multiple of 32")

-- Hex/byte helpers
local function hexToBytes(hex)
    assert(#hex % 2 == 0, "hexToBytes: odd-length hex string: "..#hex)
    local t = {}
    for i = 1, #hex, 2 do
        local cc = hex:sub(i, i+1)
        local n = tonumber(cc, 16)
        assert(n, "hexToBytes: invalid hex pair '"..cc.."' at pos "..i)
        t[#t+1] = string.char(n)
    end
    return table.concat(t)
end
local function tobytes(s)
    local t = {}
    for i = 1, #s do t[i] = s:byte(i) end
    return t
end
local function frombytes(t)
    local s = {}
    for i = 1, #t do s[i] = string.char(t[i]) end
    return table.concat(s)
end

-- AES tables
local Sbox = {
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,
    4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,
    9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,
    83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,
    208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,
    81,163,64,143,146,157,56,245,234,101,98,186,8,200,140,136,
    162,207,109,55,102,12,61,36,173,15,23,68,143,2,190,6,
    25,89,119,177,63,179,37,114,65,59,85,224,11,45,157,147,
    201,238,123,75,39,28,83,170,97,92,9,130,15,113,57,48,
    19,114,28,95,25,6,54,71,44,61,74,9,63,112,153,30,
    82,57,156,66,115,182,39,171,107,122,131,151,179,32,21,95,
    31,14,241,242,216,154,123,50,83,77,41,35,52,8,186,20,
    125,186,130,195,233,155,24,56,11,22,28,48,63,85,102,58,
    158,77,136,88,76,169,157,134,73,69,61,176,42,9,123,165
}
local InvSbox = {
    82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,
    124,227,57,130,155,47,255,135,52,142,67,68,196,214,210,71,
    240,173,212,162,175,156,164,114,183,253,147,38,54,63,247,204,
    52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
    7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,
    82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,
    106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,
    69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
    234,101,98,186,150,20,252,227,73,96,195,186,20,218,132,185,
    108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,
    232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,
    97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,
    155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,
    65,153,45,15,176,84,187,22
}
local Rcon = {1,2,4,8,16,32,64,128,27,54}

local function xtime(a)
    local r = a * 2
    if a >= 0x80 then r = bit32.bxor(r, 0x1B) end
    return bit32.band(r, 0xFF)
end
local function gmul(a,b)
    local p = 0
    for _=1,8 do
        if bit32.band(b,1) ~= 0 then p = bit32.bxor(p,a) end
        local hi = bit32.band(a,0x80)
        a = bit32.band(a*2,0xFF)
        if hi ~= 0 then a = bit32.bxor(a,0x1B) end
        b = bit32.rshift(b,1)
    end
    return p
end
local function rotword(w) return {w[2], w[3], w[4], w[1]} end
local function subword(w)
    return { Sbox[w[1]+1], Sbox[w[2]+1], Sbox[w[3]+1], Sbox[w[4]+1] }
end

local function keyexpand(keybytes)
    assert(#keybytes == 32, "keyexpand: expected 32 key bytes, got "..#keybytes)
    local Nk, Nb, Nr = 8, 4, 14
    local w = {}
    for i=0,Nk-1 do
        w[i] = { keybytes[4*i+1], keybytes[4*i+2], keybytes[4*i+3], keybytes[4*i+4] }
    end
    for i=Nk, Nb*(Nr+1)-1 do
        local temp = { w[i-1][1], w[i-1][2], w[i-1][3], w[i-1][4] }
        if i % Nk == 0 then
            temp = rotword(temp)
            temp = subword(temp)
            temp[1] = bit32.bxor(temp[1], Rcon[math.floor(i/Nk)])
        elseif i % Nk == 4 then
            temp = subword(temp)
        end
        w[i] = {
            bit32.bxor(w[i-Nk][1], temp[1]),
            bit32.bxor(w[i-Nk][2], temp[2]),
            bit32.bxor(w[i-Nk][3], temp[3]),
            bit32.bxor(w[i-Nk][4], temp[4]),
        }
    end
    local roundkeys = {}
    for r=0, Nr do
        local rk = {}
        for c=0,3 do
            local t = w[r*4 + c]
            rk[c*4+1], rk[c*4+2], rk[c*4+3], rk[c*4+4] = t[1], t[2], t[3], t[4]
        end
        roundkeys[r] = rk
    end
    return roundkeys
end

local function bytes_to_state(block)
    local s = {{},{},{},{}}
    for i=0,15 do
        s[(i%4)+1][math.floor(i/4)+1] = block[i+1]
    end
    return s
end
local function state_to_bytes(state)
    local out = {}
    for i=0,15 do
        out[i+1] = state[(i%4)+1][math.floor(i/4)+1]
    end
    return out
end

local function addroundkey(state, roundkey)
    assert(type(roundkey) == "table", "addroundkey: roundkey is not a table")
    for c=1,4 do
        for r=1,4 do
            local s = state[r] and state[r][c]
            local k = roundkey[(c-1)*4 + r]
            if s == nil then
                error(("addroundkey: state[%d][%d] is nil"):format(r, c))
            end
            if k == nil then
                error(("addroundkey: roundkey[%d] is nil (c=%d, r=%d)"):format((c-1)*4 + r, c, r))
            end
            state[r][c] = bit32.bxor(s, k)
        end
    end
end

local function invshiftrows(state)
    state[2][1], state[2][2], state[2][3], state[2][4] = state[2][4], state[2][1], state[2][2], state[2][3]
    state[3][1], state[3][2], state[3][3], state[3][4] = state[3][3], state[3][4], state[3][1], state[3][2]
    state[4][1], state[4][2], state[4][3], state[4][4] = state[4][2], state[4][3], state[4][4], state[4][1]
end
local function invsubbytes(state)
    for r=1,4 do
        for c=1,4 do
            state[r][c] = InvSbox[state[r][c]+1]
        end
    end
end
local function invmixcolumns(state)
    for c=1,4 do
        local a0,a1,a2,a3 = state[1][c], state[2][c], state[3][c], state[4][c]
        state[1][c] = bit32.band(bit32.bxor(bit32.bxor(gmul(a0,0x0e), gmul(a1,0x0b)), bit32.bxor(gmul(a2,0x0d), gmul(a3,0x09))), 0xFF)
        state[2][c] = bit32.band(bit32.bxor(bit32.bxor(gmul(a0,0x09), gmul(a1,0x0e)), bit32.bxor(gmul(a2,0x0b), gmul(a3,0x0d))), 0xFF)
        state[3][c] = bit32.band(bit32.bxor(bit32.bxor(gmul(a0,0x0d), gmul(a1,0x09)), bit32.bxor(gmul(a2,0x0e), gmul(a3,0x0b))), 0xFF)
        state[4][c] = bit32.band(bit32.bxor(bit32.bxor(gmul(a0,0x0b), gmul(a1,0x0d)), bit32.bxor(gmul(a2,0x09), gmul(a3,0x0e))), 0xFF)
    end
end

local function xor16(a, b)
    local r = {}
    for i = 1, 16 do
        r[i] = string.char(bit32.bxor(a:byte(i), b:byte(i)))
    end
    return table.concat(r)
end
local function pkcs7_unpad(s)
    local n = #s
    if n == 0 then return "" end
    local pad = s:byte(n)
    if pad < 1 or pad > 16 then return s end
    for i = n - pad + 1, n do
        if s:byte(i) ~= pad then
            return s
        end
    end
    return s:sub(1, n - pad)
end

local function decryptblock(block_str, key_str)
    assert(#block_str == 16, "decryptblock: bad block len "..#block_str)
    assert(#key_str  == 32, "decryptblock: bad key len "..#key_str)

    local block = tobytes(block_str)
    local key   = tobytes(key_str)
    local roundkeys = keyexpand(key)
    local Nr = 14

    local state = bytes_to_state(block)
    assert(type(roundkeys[Nr]) == "table" and #roundkeys[Nr] >= 16, "roundkeys[Nr] invalid")
    addroundkey(state, roundkeys[Nr])

    for round = Nr-1, 1, -1 do
        invshiftrows(state)
        invsubbytes(state)
        assert(type(roundkeys[round]) == "table" and #roundkeys[round] >= 16, ("roundkeys[%d] invalid"):format(round))
        addroundkey(state, roundkeys[round])
        invmixcolumns(state)
    end

    invshiftrows(state)
    invsubbytes(state)
    assert(type(roundkeys[0]) == "table" and #roundkeys[0] >= 16, "roundkeys[0] invalid")
    addroundkey(state, roundkeys[0])

    local out = state_to_bytes(state)
    return frombytes(out)
end

local AES = {}
function AES.decrypt_cbc(cipher, key, iv)
    assert(#key == 32, "AES-256 key must be 32 bytes")
    assert(#iv  == 16, "IV must be 16 bytes")
    assert(#cipher % 16 == 0, "Ciphertext must be a multiple of 16 bytes")
    if #cipher == 0 then error("Empty ciphertext") end

    local out = {}
    local prev = iv
    for i = 1, #cipher, 16 do
        local cblock = cipher:sub(i, i+15)
        if #cblock ~= 16 then
            error(("Cipher block %d has %d bytes"):format((i-1)/16+1, #cblock))
        end
        local pblock = decryptblock(cblock, key)
        if #pblock ~= 16 then
            error(("decryptblock returned %d bytes at offset %d"):format(#pblock, i))
        end
        out[#out+1] = xor16(pblock, prev)
        prev = cblock
    end
    return pkcs7_unpad(table.concat(out))
end

-- Visibility
print("Key hex length:", #AES_KEY_HEX)
print("IV hex length:",  #IV_HEX)
print("Cipher hex length:", #CIPHER_HEX)
print("Cipher bytes (Lua):", #hexToBytes(CIPHER_HEX))

-- Final decrypt + execute
local plain = AES.decrypt_cbc(
    hexToBytes(CIPHER_HEX),
    hexToBytes(AES_KEY_HEX),
    hexToBytes(IV_HEX)
)

print("Decrypted length:", #plain)
print("=== Decrypted preview ===")
print(plain:sub(1, 200))
print("=========================")

local f, err = loadstring(plain)
if not f then
    print("❌ Loadstring failed:", err)
else
    local ok, runtimeErr = pcall(f)
    if not ok then
        print("❌ Runtime error:", runtimeErr)
    else
        print("✅ Script executed successfully")
    end
end

-- Scrub sensitive values
AES_KEY_HEX, IV_HEX, CIPHER_HEX, plain = nil, nil, nil, nil
