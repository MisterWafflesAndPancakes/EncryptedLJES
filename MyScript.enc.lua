local fragments = {
        {t="bytes", d={39,93}},
        {t="hex", d="cd9b"},
        {t="bytes", d={197,214}},
        {t="bytes", d={33,99,167}},
        {t="bytes", d={43}},
        {t="bytes", d={87,157}},
        {t="hexchars", d={"7","e"}},
        {t="bytes", d={137,244}},
        {t="hexchars", d={"d","9","b","f","5","1"}},
        {t="hexchars", d={"f","c","4","7","9","b"}},
        {t="bytes", d={85}},
        {t="bytes", d={213}},
        {t="bytes", d={24,204,183}},
        {t="hexchars", d={"d","2"}},
        {t="hex", d="feac"},
        {t="hex", d="0935"},
        {t="hex", d="ac"}
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
        {t="bytes", d={172}},
        {t="bytes", d={15}},
        {t="hexchars", d={"6","1"}},
        {t="hex", d="c91590"},
        {t="hexchars", d={"e","3"}},
        {t="hexchars", d={"4","1","5","3"}},
        {t="hex", d="eda8"},
        {t="hexchars", d={"8","1"}},
        {t="hexchars", d={"8","4","c","b","3","8"}},
        {t="bytes", d={130}}
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

-- Disguised cipher fragments (single base64)
local cipher_fragments = {
        {t="b64", d=[[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]]}
}

local function rebuild_cipher_hex()
    local acc = {}
    for i = 1, #cipher_fragments do
        local f = cipher_fragments[i]
        if f.t == "b64" then
            acc[#acc+1] = bytes_to_hex(b64decode(f.d))
        elseif f.t == "hex" then
            acc[#acc+1] = f.d
        elseif f.t == "hexchars" then
            acc[#acc+1] = table.concat(f.d)
        elseif f.t == "bytes" then
            local tmp = {}
            for j = 1, #f.d do
                tmp[#tmp+1] = byte_to_hex(f.d[j])
            end
            acc[#acc+1] = table.concat(tmp)
        else
            acc[#acc+1] = tostring(f.d)
        end
    end
    return table.concat(acc)
end

local CIPHER_HEX = rebuild_cipher_hex()

-- Integrity signals from Node build
local NODE_CIPHER_BYTES  = 18528
local NODE_CIPHER_HEXLEN = 37056
local NODE_CIPHER_B64LEN = 24704

-- Require bit32 early
assert(bit32 and type(bit32.bxor)=="function", "bit32 library is required")

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

-- Integrity checks vs Node
local cipher_bytes = hexToBytes(CIPHER_HEX)
print("Node cipher bytes:", NODE_CIPHER_BYTES)
print("Node cipher hex len:", NODE_CIPHER_HEXLEN)
print("Node cipher b64 len:", NODE_CIPHER_B64LEN)
print("Lua cipher bytes:", #cipher_bytes)
assert(#cipher_bytes == NODE_CIPHER_BYTES, "Cipher bytes mismatch: "..#cipher_bytes.." vs "..NODE_CIPHER_BYTES)
assert(#CIPHER_HEX == NODE_CIPHER_HEXLEN, "Cipher hex length mismatch")
assert(#cipher_bytes % 16 == 0, "Cipher length not multiple of 16")

-- Optional per-block diagnostics (debug only)
if false then
    for i = 1, #cipher_bytes, 16 do
        local cblock = cipher_bytes:sub(i, i+15)
        if #cblock ~= 16 then
            print(("Block %d length: %d"):format((i-1)/16+1, #cblock))
        end
    end
end

-- Visibility
print("Key hex length:", #AES_KEY_HEX)
print("IV hex length:",  #IV_HEX)
print("Cipher hex length:", #CIPHER_HEX)

-- Final decrypt + execute
local plain = AES.decrypt_cbc(
    cipher_bytes,
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
