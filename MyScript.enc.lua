-- Key fragments
local fragments = {
        {t="hex", d="a8"},
        {t="bytes", d={48,20,52}},
        {t="bytes", d={102,182}},
        {t="bytes", d={103,158,240}},
        {t="hex", d="0e3c"},
        {t="hex", d="9d3b57"},
        {t="bytes", d={56,185}},
        {t="bytes", d={149,176}},
        {t="bytes", d={16}},
        {t="hexchars", d={"1","1","5","f"}},
        {t="bytes", d={246}},
        {t="hex", d="16b05494"},
        {t="hexchars", d={"7","c","4","d"}},
        {t="hex", d="5081ad85"}
}

-- Helpers for fragment rebuild
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

-- Key rebuild
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

-- IV fragments
local iv_fragments = {
        {t="hex", d="e185ac"},
        {t="hex", d="25"},
        {t="hexchars", d={"8","3","5","9"}},
        {t="b64", d="DA=="},
        {t="hex", d="6f2a15"},
        {t="hexchars", d={"8","b","8","b"}},
        {t="hex", d="b4"},
        {t="hexchars", d={"e","c","d","e","a","0"}}
}

-- IV rebuild
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

-- Cipher fragments must be defined by the template generator upstream
assert(type(cipher_fragments) == "table" and #cipher_fragments > 0, "cipher_fragments missing or empty")

-- Cipher rebuild
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
assert(#IV_HEX == 32, "IV hex must be 32 chars, got "..#IV_HEX)
assert(#CIPHER_HEX % 32 == 0, "Cipher hex length must be multiple of 32")

-- Hex/byte helpers for AES pipeline
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

-- Extra convenience
local function bytes_to_hex(str)
    local out = {}
    for i = 1, #str do
        out[#out+1] = string.format("%02x", str:byte(i))
    end
    return table.concat(out)
end

-- AES tables and math
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
local InvSbox = {82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,214,210,71,240,173,212,162,175,156,164,114,183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,234,101,98,186,150,20,252,227,73,96,195,186,20,218,132,185,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,187,22}
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

-- Guards to ensure prerequisites exist
assert(type(bit32) == "table" and type(bit32.bxor) == "function", "bit32.bxor unavailable")
assert(type(rotword) == "function" and type(subword) == "function", "rotword/subword missing")
assert(type(Rcon) == "table", "Rcon missing")

-- Hardened key expansion
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
            local rcIndex = math.floor(i/Nk)
            assert(Rcon[rcIndex] ~= nil, ("Rcon[%d] is nil"):format(rcIndex))
            temp[1] = bit32.bxor(temp[1], Rcon[rcIndex])
        elseif i % Nk == 4 then
            temp = subword(temp)
        end
        assert(w[i-Nk] ~= nil, ("w[%d] is nil"):format(i-Nk))
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
            assert(t ~= nil, ("w[%d] is nil"):format(r*4 + c))
            rk[c*4+1], rk[c*4+2], rk[c*4+3], rk[c*4+4] = t[1], t[2], t[3], t[4]
        end
        roundkeys[r] = rk
    end
    return roundkeys
end

-- State helpers
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

-- Guarded addroundkey to pinpoint nils
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

-- AES inverse transforms
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

-- XOR helper and padding
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

-- Hardened decryptblock
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

-- AES CBC
local AES = {}
function AES.decrypt_cbc(cipher, key, iv)
    assert(#key == 32, "AES-256 key must be 32 bytes")
    assert(#iv  == 16, "IV must be 16 bytes")
    assert(#cipher % 16 == 0, "Ciphertext must be a multiple of 16 bytes")
    if #cipher == 0 then error("Empty ciphertext") end

    -- Key schedule smoke test
    do
        local ks = keyexpand(tobytes(key))
        assert(ks[0] and ks[14], "keyexpand failed to produce round keys 0 and 14")
    end

    local out = {}
    local prev = iv
    for i = 1, #cipher, 16 do
        local cblock = cipher:sub(i, i+15)
        local pblock = decryptblock(cblock, key)
        if #pblock ~= 16 then
            error(("decryptblock returned %d bytes at offset %d"):format(#pblock, i))
        end
        out[#out+1] = xor16(pblock, prev)
        prev = cblock
    end
    return pkcs7_unpad(table.concat(out))
end

-- Visibility: confirm rebuild lengths before decrypt
print("Key hex length:", #AES_KEY_HEX)
print("IV hex length:",  #IV_HEX)
print("Cipher hex length:", #CIPHER_HEX)
print("Cipher bytes:", #hexToBytes(CIPHER_HEX))

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
