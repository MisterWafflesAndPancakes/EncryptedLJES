-- Self-decrypting encrypted script
-- Randomised AES key fragments (rebuild to hex)
local fragments = {
        {t="b64", d="qDAU"},
        {t="junk", d="9bdd5120"},
        {t="b64", d="NGY="},
        {t="b64", d="tmc="},
        {t="junk", d="d3"},
        {t="bytes", d={158,240,14}},
        {t="bytes", d={60}},
        {t="hex", d="9d"},
        {t="junk", d="e302"},
        {t="bytes", d={59,87}},
        {t="junk", d="883d10"},
        {t="b64", d="OLk="},
        {t="hexchars", d={"9","5","b","0","1","0"}},
        {t="bytes", d={17,95,246}},
        {t="hexchars", d={"1","6","b","0","5","4","9","4"}},
        {t="hexchars", d={"7","c","4","d"}},
        {t="b64", d="UIGthQ=="}
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
        if f.t == "junk" then
            -- ignore dummy
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

-- Disguised iv fragments (rebuild to hex)
local iv_fragments = {
        {t="b64", d="Jf8="},
        {t="hexchars", d={"c","c","a","8","2","9"}},
        {t="hexchars", d={"7","9"}},
        {t="junk", d="4dc7"},
        {t="bytes", d={40,163,206,126}},
        {t="junk", d="f4"},
        {t="hex", d="b8e8b5"},
        {t="junk", d="62"},
        {t="hexchars", d={"6","e","e","1","a","3"}}
}

local function rebuild_iv_hex()
    local acc = {}
    for i = 1, #iv_fragments do
        local f = iv_fragments[i]
        if f.t == "junk" then
            -- ignore dummy
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
        elseif f.t == "b64" then
            acc[#acc+1] = bytes_to_hex(b64decode(f.d))
        else
            acc[#acc+1] = tostring(f.d)
        end
    end
    return table.concat(acc)
end

local IV_HEX = rebuild_iv_hex()

-- Disguised cipher fragments (rebuild to hex)
local cipher_fragments = {
        {t="b64", d="K2qM6iQiRkWYqVso0ObY3ZOpdprY1+wOr4PxAoalp8a+XCCFNruClpx3kFGyKqr09T7vQRXyZny3vcMJsVJ4DoRQ3MYgDJKJ2DiEm5fY5hEN90ZLGSX/E9rF4kJsNNUSRuZfWSL/m/MMU7otc/ZZc/64QWX7Ub9p64Hqb+8a1fn9vv7epTwfc3j/ZHVn6h2USJvD/9IDE35Z7tBOMa4cVg2zL1TlNFfV9bhNNoWDtQ4lYOGKCLckdQ8LkgbypSjHWCaNwqN2VNdp7GODGCeigSdMb44corkloww2QViY0tOT1GrouA+gXBPM28A/shfNtrNnffuVYgZ3Qn1OkQFvLs1SmcSCWT67KQWBYpCIZ8ad7dLyC7Pje2j9qEYfwMDRau5a6BtAowkmUo6yrACe0DH7YFmcRGYYsZMP5A/adsoJp7G50mud4IT8P0Ty/ePkM4luxBNQ2MnrE3prdy1q/z7XJkPJIeHctDug91dECwoyeDIQVGK7PFfyN3sENJRL"},
        {t="b64", d="62wt27hay18nvxZ168m/sFlCfpdvKbI7/iWqdQf9JAkCgHFgpRaBMZVy5VgTbdK0rhslWK5Dyf2G9L+YKex+z+XO0c7CfENG33b7SdyMLwEwqvn3FBbdIEj5mSJqqDREX/wDRodRvzP3U/oZikcBfy2yBclrKH4DBb7XsYSlkW39yUkrU+sbQRTKiJLYEEMk00fVd4x/iE6R32CS8M5L7oxnqwO9cdZAECZqQjIa3T5ASBk85K+oxu3pXCJ+qt8/SYiqYjDuYiul01f6m+Jnni5wFltOgN75Tpcir8mNj52WNGZoQF4qFhAY7vYegU2S+N8333wVioyGuwz3JNT7lJZHjHCmtLH0UGlFM0v4MEcUkv4Ix3u1MQTRYGk+hUtmRXz84K7nKxgnu/blsE0lYjuaEw5OlIhl+lq7udj9lNug1CRH6Sf8/4HJeLc+b6ZLNzXwtfC/CNW1J2siuREnUPM/f2xKtdL3wCiGc3qGEmKT9wXKfZPCgpT4FPall+Sp"},
        {t="junk", d="01d0"},
        {t="b64", d="YjA3TlUrT2D93CCokvxTPqHlPB5sxiayNSyXhENY+d2PR7wVp3oQrL7Y4VkTwtwVdjLIZuiAx7gXa01L0SmjdyaANfcbt8MBUaZxMEPqUptkKwcuTLlUsQn19CU8XVObrn0SihPo3tEOsBeGVqMCW29YOpxQPS4xE6/rIyG0WGn8TPLifcMX9tOcgaHnG6/kmp5PG2izvEGAe2fkt9UFMPug8X0wcJYc9CR5OYupfQu+M1j/nczzpgsqavLVBbpt3vswyoXcg+S4cHQ4zOtlhfu4y5oXLEGUlw7WLwEdtaeRtqRjgyjBmWGFDForhmAVL01QrcP1Y4tJHEs2ZX4DUlr9vSskE86GJ1k4ya+H/72jZMt8c7u63reZhmB54WO69nVooMuqvw7g0972cZOhkxYNANXaLH1NeXeiZGLgI5Q4mgMyD1mnsQiEN4jkTGNOt1f/7/AL5AB6CsjmqwgINbq5svoHPDZApZU5LzekRmlTJGzHXVhp/a4ql/OLUjkY"},
        {t="b64", d="11ex9wMFps4v8s87JWTlcC9np3h8+Vt04+eXRxpbO9uV9JUw5kp6pucAtqX3CgrAK48VdpmyHyyy3wBtk5EpZ/Kxn2k24AdSf9orzZxSI+gJrmwllpnXoT3Qh6SjdUSM/KtPNq7MrmUTMzJo10kEkLfMamkQL5xJsGLyro8R8Zr9zCgDC5l0JuebAflNSWuK9TsDClD0VyuM0Jf/cS55DYsOJzOMnDqcmsmhrXwFmjXQopMlujC6JtB6ajYgAHiI4LE10ddvKh4kzQqC2AVSCQ1MFJbWm9tBtXq+SunJeJzHGD2L7EbUT4qiv3HKynWGXwbudNZYbE1J0poNYJNpfGGGdo+egGf2uUowrn3elP11i6m/6rJVzF0iQGZmmmR+0Zxs1TaX4TVA+XtavuOixCd9M2fu8qY/4ZuAxgvRJ3DdCdmAYOQuFlpLUF9R3Ow+sgzdq0wSUlDOG2WlIHQk9h01K22+iQuPvr5BlFw3lcT+Qa2oJmgkesbP3PGgCMNI"},
        {t="b64", d="NC5JgalHwniAAiI1nDOkq0eOkzJReiALTMgtN1D2xsxr322M9MVLgQfXxbP0S0k7XHNTSSBPajQeAI6TsdVhERC2Fq10DfmDVVv4OWLe0FQHx2Drqs6qR7dBbbO3MGHOFA8j5JKiIhwIMc3FjltwciEi1HA1jxyUivfLwamRyKJ/h10BtFYC2Vfwr2HC4cGjNJCgOLY/7dp2CG9zWWgvmkIJbjBip1bwW/a5nxalOe9FewjKZHVsrsOXjnDc5YlJ9V2e5jIazci/MEK7MUe8rfhHOnxN/rVI3mKpkBher0jKIQfnkzanelbgP11TTr68mYvhYqSURcnPurv4BED9Wy4p/NtQX4XtbBK+oz/N1p7hT945frL/KkhW2SDV1PvAdWCIx7inYa8wEdLQi6YeY1txorQjh789qXGeCzF6AoouWq1mPCnv+n0SNavvLYtutRrSGMSGLSUivmIEGqxju3+di2U0ivDdd7BvK0KwBFRD7FdPuZ7wDUMyTHL/h4Se"},
        {t="b64", d="X2oAzdNbgoJX3rspkSOsCKJb30qA6t4ihYx5y0LqSo/rmj1NI40++OpYANOB4Y6kS++jHrG37HcE4bTESyRgqRPJ1EJQEVGvfadh1FW1oru87uKF+0egQboVsAPf65aRhwkt6pFTpO8YXDyktdrVaoJGzqt8IcDrWVf8yVAEgN9ovnwP7IIizLcyekvKiQIsN6gG8CDhunuyB7Dzes/qJajzH3O4wun7mMREEYk7Xf8m5xifJkT+EHKVMXdHK1uySKdXALecPq5mJG/fSQOilcrZenb0o6AVo++coIZbVdv4CHUhjCWbnT/YeTMyb7ZCaCcNuZhdgPCuUDxnwlP3goXEN4m0OBgxH25LkoSDSxxozhBwghwLfE5H/jxu7K0EzZeR+WS3esYKCogBoY2eM28lbG5+tu4EVInnxqeyEfmeggl7G865bAm8mlb8v2adht7eJKHIp0qTgUWiDtwLUSuwuufx9JoPtgpwFUUevGQuyWjoLEXvIHxuH3K/Sd2m"},
        {t="b64", d="3UITgWig5+LkHAX5U7MIky4WxlGWjh8CAXoczbwp47/tHqaNDYS4pCtBMyNaINEVfx0b9SUSa0s5UEJzl/2T7hqm7R3ZB08v6qJNsGJsrq3AArZX01XPHNZhiRI9IembuUDSLyL55hXf6Sy2MAH0W/PgFVHIDeUPmjKXg9V3soiP8Ynt5BJcdpulpu3dsUseHBgM3D+vDG8ay0nowjAq2AxMx/Zk9QsODS/EIMgY7qfn9MR3SNHfgNzuRjwdPR8Q7Hquvu+IT82mIzqfW0o1qV0zyAv4UgORFjemx4SvSciI5/pqR+zy+s7XYkoMt+IVKwe4oiYf/jzlCh01dWqSzVsSCM+yqk7/DSwMtOy7z1mPLjGhPI1BwMiAOLoWznUfIphRCkTKON7M6aHSIzSPeT1ayTuQ+7JpYHY2+tVgSsPwE9H8A7EMME2Mnn5d1M1PH1vbZ7kYgvG1HEwYjQLEyDH7/ODrEyD5PkD8MtUP82K+kVrTi/RVsoRiYvyevgir"},
        {t="b64", d="FEVUa+2f8qano3g1zmMU+YSiN9w3BqUb3YLxnqOZsSvJ5sGwohxfz9R3DRC5LS/FQFwY5pZxbfx7d13t1Rt631dGa2dw+iUT81Y5Mb2Se555Sgbm0AcIsZWRu0zyxTdWolxooQS1n/CXzPsAeubToCvJkmRh7KbB8r+WLXUfDHBI7hiNpUsIecSv0rR5tuRNUuGi+4Ld3tn8mIwDiL1MYrF4CU5xt6uN8IQK/iiIollj1MfBlhgVO0IF7YHf4cNGLp2D6WFJy3csSOXKefSDVjWFEU8F2OncWEEUMtyssV3dsN0RqTbi3RhLVzossrCtCccb2BSG1rpHfkwRmAzooamgXOZsHgolskPhm32kqd2RA99DrAnnQiDN68HQa7mgSStIZpuNFf2R/mOcNN5MJXewNWU+uuKNl0TBgDCWJV0GHF9EoAkw8rAx/coYv8oOYrVqxvPwN5TgG21S8ZIO8ireUAu1PrUFNg10t7VZghmKgsYFJbWQDZFc35sTtzDJ"},
        {t="junk", d="f0"},
        {t="b64", d="id8P+wf1YzxEFEeCa3GcE+1qEdkj74CPzL3IXiVKVIAAL1vsQJAWm98TdMVUrIzGFVzIq4xW8q/whA06IbN02S0RleHxjG16KRQ6rRIeIvj9yll3KxRzE1hBd1yk/gTMog0Cd3AcoO7tGhoJv6hjW/C8QFUrjdfEebgCsNL/L6B7fSxVGC5oJNdSDY0v+x7VYo+A6fF4db/0WASrg3znva45S/p/m+VA2DA9xmJ1k6Omk2wqb/Al10X0Z0lZVq++hpcsK+dh/fFSY6POqAtH3tJxirpvIeRrPZKDpEtXA/oGIkSSDS9kKlEf69OroX4uvoGMQALecM6mxfQudyhiM+Ddb8aXackUMm2XqRyGx9liXxYpwf3Dlwrt4zhWkGVzlo5eQFih4kt0nb057E0UGiOT4Ge9SieE/Xet1Ucs5cIHmXlBtx4vw7YLNoviqJO/ffCuPrsIml92UGmT0eAulRKEc+fCQcW6UpN7BkkizWaYc9Ii6Uj87s7482T3ELhC"},
        {t="b64", d="L7QwUcxMiRmvfTxGf3Uqz0y0H6un1brFk+PefoelcFrmII1/C+yFepyJME77V4pAe+/zazA5gc0IpAjktuaxCihXDQVQPMn4LoCaSQyk9WCdd8omrJ34q1zJIKMM3det0ZjTC8oaIW6p7HCSkiL896NtejJJW5o3ateRC5FXjqQRvfCgpvFLxIc/wl85NJ3uBKnjFhTe2/geqO9gJevmu13Okjpft6poz3kAy8+IkgvEGPCtDy2Qko0WlUUepnD7Si1oVWt1DIIVzSoNxf8tYWN4BFIyaM3T9a/BNlYqyWfBWskbPuIxcbNqMrfw/7Mm7B8IN+a0nUpWQEtuVDKeqX1oFvQgypk+S+bxmqM80oxDbfBnOnNrrFZDb/jn1Jm3QuweLciptSKihls7Jnd+7YBAGoU1iupp0uHQ/Ag0hhudUDdKf2S7IbQNWCuQCeDFBzZezy7rWJgPXFdKKz3pVZiB2hXwVZeRs++OtvrmaFfVYYGFySnhmLWuRqYwpNLx"},
        {t="junk", d="5f"},
        {t="b64", d="hqe7oK5Wp5jYNurNtu7mZyF0rSofD/Et7Hi//78sN1RhF2HrjBONjKKQVIGov5ObuG7QuXdccV0AQvxrqKwTAZrgZlqv50wUSX3VxTzsoXbI9mpJMD1sM3ktEg4oDdkQv6saTB41j3AaCFRDOKUcUtNF+FyzK/xBrUThRL71dqTZfF2u94fRgsvm/RykbfA9YSIUS1V+9nqi788K0zJuCXaRLQgyoYyv2eNANxOPJz1zhc9KiJ1SPD9e2ejFErafB3k1MIbFbMR5ia58/y5W13QqM9UuT/u7ogRBv/N23QLK/4FFhcgN4Xhx+Oqut/8uhjUW6lH/2koSuzC9L7ahgUihwQd4LpSlrUwL+SBwwO1hJdVnUPbWzXXdQFQhmFFPznUZ+Xsi4r4W6HIv3zHBxb5kUfX1FX6GBSUMdk4DcD1RGp6wCAgZKkKCAfLBzcH/ye0pW7TbYpAtTK7TRt2d0mGbf+NMquhmy/dbF2NUh7+vmD7pSv7KOaYGJfobyBHt"},
        {t="b64", d="YeJlt2shNcOVkMa26ROwCNR2dSWgQ5kQL/t6JRCAjw9v+4YLII29YGnDe7B6199hgDYBL47k9+NLRFA5ONS3YsEBXeQqJ8jPw0ZPOsFigJu+Nor5fB/wmpvvOr4FhQe4GmogH0ZATew1OwDo5gbgR0AajJylG0XSFFk/HNVaATC/fetx1poWb6zHSHNAFZOhF4QhuCYigm2y8z6d68npMrBvXa0vWEif+YyvJllId2mE/r60CiyyuemOnKvP8ky6nB3kAVtEJ+mxSd0HGbpZElT7OSIueLuASb486OVR37Y79+N6/YXoC1+RxUlRzy5AGXkEdcDQZ6dW9/laIadYwSBEToY1gofTd0AYbyxGsD/o4VM+AJ9gMAHugI7aIp7PbXPt1QTw8Bd/Sdx6wBy89rx0316uunVtUA/SyQQp9FdkRQTJwIIRa1Rw6xruQQx1sFrFbzWF0KbrV6dxAhDr2PbwgmS1rxO379sErxXRHMxC7cCg/QTfVWRoejmAac/6"},
        {t="b64", d="nzUbE8YAnTEbZfHa5Lp3x4jni+vAe8WjTC020iiWw6RQ+d25h3MEKJ0Y7NjY+cMxIczPG0ODxywl31ypsWXl+ExF/RVvS+qPVQ7Tj68xooIoS1rtXxgiNRrK1EPKKLQMINVMZaIze3ouLchQiwfUoSzv11Y6guVlrWaY0fWssuk0VvVfr3XEPsxKfSE5EqjcRnyhcKvA8end32349qkuEJC9kdLtn8yfp0UCZ/N9fwXV1Sha2Ti5JAllFdlyqFLyO0BVUxCqjoR2nlNrkS1aj/mL6VHqKE+WQW+lS+QqLA2fpzVXB9QHZAr/l9/Y5FNjs5emKNT0WLAnqWvWAT8bWPEiADXVkb0cp8eOV7bYUDjWn3A8gvVvKXwZo1nNK9zQElLLml/ACZU4EF8es/8lQTmh1s2Mn91slvXNjcYsBc8kX2+awJAnUVl5ufJ05cM2DHy88Tr6cTg5ZZUodOdpMva2ASvO+CDIWd9nOA5eDKRAivzFXoXWIudLKEn+yLlO"},
        {t="b64", d="T+1Ni3eXuOXc+ACF9sQC7lpt/gOaWLs4Wz5AJ1hac8elcQTxpynSbSd1M0zrw6e1sZR5Vh3sn7uWd9hTAK7MOaOTU0i7jBQ+jhujqcDbxsKyc06EWehNW38vtey3mMAgbWMyWPpSmljdGGL5Lf27xQMicjdcdxw729SyDkHQ+/DuIiffrbz51adsomKaFbEWR8XBovGvQv27H9UqQ9QQCy7WFUewNTnP27Q6GKqcy3G+epbZuPIR1qm5bx3R8W0e+GkSSO957DE2rA/vHQa9lBkUKV1yoN5UMmNN+oWhwvp5hnm3rK8IT8GUUtu0p6C5wzhu1ratJHP9mvOlTxcFIys4owBpTjif0edC82eZHeCPZr9Ssr3IK9Kw5JPeP00Z280a69m8M+r5JttkQOBwI/2r06kC43lRWK2mlJwiGC0/QkIBuNbF5jZY82AK8sCqwjEIc0ZR0SAAEa889NNxoAt1hFtkLxIpOVGsQrxWMd3u6W52/NLk8z/pk4BbmQYI"},
        {t="b64", d="asr5+ukxi3kw3igHUkFkqBbbz6iuqsg3aW0eHrdoSN9Ab7I+3znDKoCKDKPNXRznzPFE44aYq9DDkEcg0VZzPg9WIQ/S/adVhmi2H5l/Zeae1tt6MuQAUe4Ww04c7iD4pI918dEFH8SK+QZ4TDVk/y6niIFNFYZ0H+eVwMzbrXdW/U+k82CSxqA0EvqVh1YK1vlUOS1nhBm7VmCGeH4fCsgfei1OM3LdABvmNZQay2K/l8+bnfYDz1ntA11ykjUwrkRctMnd+kPhcboNMA9zLngcqxpkCZ//T9Fzqqx+Qxe50Mw0Isu1+mdB9x5JPNulQo4I/tYTGyozpC1VP2Os1Yz67fLJtrfe+/Zo1LcQ0QDHauQI2gdw4Ucq/kpgbLB9jtKk031cSjgbrUDBYhx/DsuFXR+Hzt/l6tr5ndDADrhHDK5/DxlGG272mS6gx8Wda6kPyYyuBYKO1jaA46Enu+2+zGC5EvmLYNJ5PjOXSfJQ+nXAuVN9bySWdG5JK3pW"},
        {t="b64", d="qWiW8PAEqfR1QYEkcjoZoqazKUM/HkLcjZoFrxZ2NNSw9IS0VAWq2gskJsNXtt0iqS8+1qFBlT+8PDdMqFCTgYUhKWSumsn1UJ7nowqDr5A5w6ZKoK1q5nTLW/2FfomxUESbCslk9OG/47ThGCjUG1/2dKXHgEyIGVy5AhxIOvne5DwyOI7mIJ7oeN4769MjHuwh7FU2oGVowfKT4+gwMyoRsgUF8cInRllgkGNsLFpTYFBkiFYpSaYYDeXss4wgCxwklvuTEv4108c9VcWyPwZ0CgLEf/KC4m9OqOhbTBWZN2jvjIjIJRM6w0UDjj0DQfFoW0YYtNC7sKOP9n0wXntkIIbk6iFx78iDGzVvwiJupfh+eRfKn6bSqnLDonnxNxwtxK/riIdJPgaI2ylVbZ5nLy34/D+mjHbeNAIqCWWyi/hdnnUXf70/dF9t5YpF2Ta9E+e6YcvFFNbiFoImzpbuo6cmUwI5S9eSdCozR7CNKvrmZJpQqNdbRw9Vx3cx"},
        {t="junk", d="b0"},
        {t="b64", d="vlrc20eNAyllr101INdE8RZ9djY4etPxxaH/8gdYaG2rDFqH0gtulYfVoDcQaV+K/1r+hXWBmmg9nKZz/Gu68cHMye4e9Zzn9uxBJRn04Un+kPE1dMtSDxc6s+Ia8em2tCWG4Og1lznvK1ywmauZ2jGpFbUkGDwbQ+P1JLGH9RH7BCVybgKtzCbGct0tHdD16Xnlarfk0S5H+n/7rxJKMBbYXYs4ptVBFNDn/KJE2RNmHTh8tzerMVoBfcE6gVBVGuCSoKB8KFqhG1HlvRjK1u5QdmprztbmT35K5tY1yotnscuDpxlUp6N1+q+NLBCXPkBAkoGPGM4pkhD0dDIPoRM3cdTQKpm9Nnl8XFq3CzItpzHInnuCinjOmG8dlnGfgPuVcnrGuHul+XQ5bAaO4W/Z07mBcxIaAlCYyXxBA0WiITBs5ishNN5fPrsH52cy403RmnF2LP0iDIF9sndGPxJCU27MB8YQ3S/HkU7BWIaxfCroc4vceHF92tfkqWic"},
        {t="b64", d="Tbi2Dsm7hRRYIA5k0Os8+uCMdsCKmLjiXQsC2ZeuJuWuw1kO1y+iZ7elZpym/8cjCv6Mp9roQthV4yjOkyASUVTL8yq00CeF9bpCwpEAvZRsxt17/YZB3+8eOlHEgi+/P8BkxqBWl3N+/OKjuPj4JQhwjWVJpBKvhz/H2TQwUJynQFd4x+eu8aGfSmxbR8pFKDTZY5POpTVIItFUSFCgKT54zBN5h3GS8BFTCJVYypliyFMSbUhRrPYJVYw0JU9ijB7oWfz0vzXZcjNuK82V3yx0dmnWVolhEhoipz5+Z8TMaSPuvdYVWZooq79elsCekV+RNI5BBOi5xX2COEJsRts3cIej7WAYFpVC7nWhnGtUU8QupghHS9UcSbYRSuFiCCNNwYNFePrMxVkoYRLWQ7yG+LUBlb+vouutLrqh0Y5uPC8hmFuklLB8JIpTMImiBUaUKXPCXvUQBAeVjs6wQZW5u2Kv2xoAPNWoqIyFH8mScF8eMcZmToobGBd1gJwl"},
        {t="b64", d="xOIXBSK9Kuv5eVkgk7903hDZvxo1TBV8lsL7zMBnnHBCxj4UdMso7lsYB1DYa5VOPTAZOP/NTjzpGFVPN25Prg/kUFLayuktn37p3tJfNFkGlBbd9wYczBms6QOzxO0wIq0WLmLo+cJNoenKTC0oPUgk57+sddFCHadyaFjm/bPvMfZWM8PN5HK8CCwSnEeIW79K1dDnaEGf7cHGOdT277s2RUvgmAawk8/3VJnGcXHLnCfShO3NzfsO15mnL7I8WALT6EQwIXzuQEhNBoTpygV6+2VD4CxtGo1E9mhNwCN3Sy8sxAtwVnbCVYNpx/yPxszOYK+BuThATHDKsbXGgC3+4nMJKLQnGckDmwiPXo6lZ3BuhCuUDPin21H6ChPWiBotuqD/rAwsBIGSqO9jDolwqhExcKHYXdJbvuM0VWC74TN1euc8EdkI+UEqHbbfDYXG3gKGQcrSnEyWZ2xbN/owPZQXh94U/5mkpDbY+VxQjmroh419M48ZNWWeu0V6"},
        {t="b64", d="g1JbTCwNl2FYwGOxqHLaSkF91V0wnJekC5J2whN5eDoDFOLewPHMeHcwjHHPg31MYdgir3nf04QuCwXh0hJjdU14UIUH9vMIr+kzWzw6mhv/uAG+B5dhfDb9xUHVsOGg6yoDems+hEWH9BVPjo7aw6w9Wtn/I7u9O1nlDsKm5Ewn/9/3WYzdHILinuX5T3rCYWK8WlrEpxWofyml/7MYxrMGqyWECmZNYwFbUSLm7IZD3lZNYAY93DHz7LgdJMYTahesgTG9tQ59yHkxsATYLPQWPJnLLSdOBSxWdWFd73cOLZmZ4ULchq6mI1WhHtXyyj2TJYxFscpxGKfcKWxX+AwZbQknK7BHVRWJJc9w4lVjVObn+ECJ/qsEajbX1YQFMeg9/Q2eDow6LQzIAYOsXrgJN43APCD4p8YHklkFyLGuiRqEWX3H81k4qosKGr/O49ISOvx6GHWbphN/45ESzW8KDojk5iurZX1Ssmxwh07Dm2Kt09FLIV9hCHMClCQP"},
        {t="b64", d="HsaTYLTbKn/FcVJv09DYNZ4pPQ7S7ly3SqkUiNB/ci8p0Rc6P8ZxAjHb94jc1MvrSKwDpBiLcUTDmHzVnl0Vxw+tV4d2hs6ZlKMMePcA+o8MxgyHzqPYCL9BYhQi1iQNylBChSp7wB5zDuXfAQ7ONb+PAQHkQyLthV/MWRPv2tqjLLGVqYmzOfYntBbH6JGp0zEXWBb7WGKNGDMT3zaIOUwuQ+d8wnasZYqa9rqtiObNbGy4kwNQU4zH016/8+GBpc1C2P2gkMlCxMAplMaki4cE4FhRTEAnzQnSF2aeYUd9YRYWuHUVfCOk4RXAtqXKFtcmzuelk0v7NBn87L2R4229B9frLzqoluwS+8Uq4FyMH4f9rJrJ96eZ3E4QMZm74TtqP0ZgB7QQaSaf9+nyDst4GAh2HNlJ1JIqMFqW0IKHQIaiq7qLRd5hRIZiuc985t5AXZYyPbaeqDXrLXmIg/ud2bd1RlAsdX0Hp1Qe7mcG6UnDZIMclIr9a5ODKp7v"},
        {t="b64", d="e1AUWKfpugV2y8TaD2rfiwYqy1xAyAvfd0QX4YV69micSuPEYZcs9mczjAAjE9v/XrBfyD7usWn8SIVcqMXlKv5geQAzlCYm3CDCiL5DmmaZc1Hv0dL+Si4yqxysLNd02PYOJkYKCweeZZzy4OUw0VBXMo+xshWVqH7j9Ogm2p4MSZuykL6mB8r0FUx1Ahsdkes0i8CazpVabCsIi6oZAmyxirGeuZlLtWrdVElWe5WJzavKLLiVTEStXrt2efiGSL7P8ChxmkkaPo5OP0HWy9OPLBFbOsxEtUG5NvhFCkvakWD2Dev0o/26sYgrD7FBsRdQK6DEM7fqZDsZf1wnH3KXAaQ6M4aze1aqURci0qusMKU6otYFYBbwHjmw6hK6kDv7+p1Et3nXdrmmJMcMLRKEm8u8bCtW9kT9rmiF4SsZWZIGsc5vp32IbTqy752bBQ6vDDi4hKL8vK4Q3sPZ7qOo1rvS5MJrQLtbrK6RbHrL4ieNNa7IV6hCML9II4co"},
        {t="b64", d="fSDKUePH6dTYdStZG+zAHP3nESZ9r3TMzNeao7B9Fax4MFOKLikz32K4/Vk/R8Q9AUW2iaA3hbkx2XT/e6EbkhCwrE1Pn/F8UwvAz1P34DyHOZk18QAAgx3R4tOm0K38TlBJcHyHJikwFwl1Lp58B9Aiwsik2FUfsWmg60agw8VtkeA5BE6zvoTtMJyRGZeneUE2d7Pgai5Yw2mzjoqEnTnddLbiT8VAvuNFqY9CK7igI3X3EgyH26r5S3mzIRJ33gtWvIQPqMvfHiqe4qiS0hKN0jdvLndvPSTY2feCg/sa1ICRq8panTujIeBgCnPjfkRsyk4X830hijTDokaea5LwAYGMqZkuZV6yfAZpzWk8NifncXYRdDiAGv31CSt7+ktY8TMrl2Co50VGiSTRtVQDrbdqxX5wYhAtTuuV86xyDKgm07kBnjc/f+sTTrJXna9OTPO6lMyTd3lkofdp7ZBoNagnTRMTT3fFuTF90rX4O15T39Sa1JNxItY66OMy"},
        {t="b64", d="wZy04zhEWJKBMl+Xr9CSRngTw9zchiP84GBgIJYF0NbL/HsNwjeVQAID+OJDkVj0Pt1EX28C4OUV102Fi738DIixiVFNqpkTmBOnkj7vZeYvOnwowXDpAH61Z6pQ62kNV6ZnB1c7+T9RqXgz6uGODEqldiN6Eq9L1yJJ9X1mgpWF/o4IkPlkis29SdyKLn+/9krJxu2clfUMC79fY/GmUQMAiqZbjfi2L1bVSiudL+TQOWZEvwSiYfh6n/NssbGcUXQvJRxaP8bDSHm2TGZh3imorAFLEaQlCNDarY8pWRYrkPe/I5e2tV5335GXXT0HwwH84Z8ZFr0j89/QZROGdftgAw80rfcWDLbTrq0oarOrndZ/NbZOkEALKjoLeTDhU6zQ6+4y+gs7NRmQbh9YAbXzIHnMpETeWVqblnRm8WDPs9FFHyu+19WqC1Mc2e1yLZeo9bOKjCj1ivzt0niCaJaKZgHstL7VWXjv6zLabwqafe/f3teYOdeBs6YHtSfg"},
        {t="junk", d="c7ff"},
        {t="b64", d="U/TEC7Si1yeoyRS4JZzvQjyEk4V5zhpvAg+TxxT3KVIh4Q4zChLpbW2rmzGXg1Bou2w5wOnfjRKtQblK3Hl/C928NoM0eaoZHFVM0nW/VdnoxBAHVhjOj5ZFkHkvCPhjkGOoxgPQDyv64IQ3l/qk3zdAVkYHpC46/XcBpLPRXCRha/HbVHFquf4IK9Gtk5Fr85N7E3j+fssZBgxMNeVC8Y8c7w8ZZQf0J9kuoyJwLaUqPfN9hpzf0cV6GD1z0xsCO3ewD8geM2Scsw0UnkYxSaLPu9NmsuyDBeIhyKsHqJC+jtKAViWDZ/4sSdCEq+ULXQiFS8YDJCNlnfKqKXrOI7ZkzJ0tMdVTatRmWlWxUQa/8K3rJhqH1TjAscubUIZxHOmV51AHgzHmH+RXJzE6EG4XJ3URzT0xjqX8ZLATpC5x7GKKRNjrfylgcHx7Aizd3jNnepyYd+1L5GuzgxA9Sv3zPNX7Riun9x3liP9cNcw1UCwHoT8BHJwnwjd9ysHg"},
        {t="junk", d="5eaf"},
        {t="b64", d="3lfVeBqkC6WzM0ff6p+F2AiJNyuareMhfF7V047FRJYEjSZ8nJEw5kCco91yIPfahyqCTrygy8wzLii5KqH9uo5Vq2d8rS6gyF3UoLETA/oR8WPFfpL8k5pUvKDSDJ1XMvDo7qtlPtOTxttP0mdd0YEnGDeKZC13/l5ab+9cRjCamZbGiVo3Zwhfb/KpVErjS6ptMGSZpPal/BtM7FeSY9BferMSZna1LexD77oCEKbDiLfe0LPDlDcR00OIoMT2AD9EYyYYB3naryAbZUwID1XzBPVfq5/F2UUfFJUzGu0YQl+yIB6FU6K2qhtBRr2JrwcPjD0MbkOFewS0YEi0nRKXGGv3bzMlBupETW4Q+DYZXGjdXj8mF9q+PjKnsCZ+jxS4rvaaGmDLQHfyNsLFf8VTmJvsFDqr3J3s0xH5ThkpdSoHSfgHAITKApKwD/HtBwTxA+UH5GxYvrUj7iwsHE8+AWZCjR3AYWe+sT2L8nilTgXy504sIvWStPrhTMR1"},
        {t="b64", d="YrUxk7fqMB7z3dj6s2luAUcpFIgX/ZUjyf9GtcUohnSVtoYcG/dGcAO0rx0k8Wa8573se3SoGbaKMjCASX15EQGyRQEOo6Ozt/7HDWHG8NHlc2DE4ToIK2dzwy3J4ndkcpEMNY9AxR7XH11trd0pRyDYcbkCA2NO0CLb8x+ybcP2wl8qDAgnIMlh830rNxaZnk7ZU8Z82NIiCvrolCkREXspfVUHnQ2pcvLUXJ0HJqcPiNoi9NpuSW0pRYaM8kIYshsoUkRjF308IKZcVsthkNK2XT12zQEHf67uJmoYnKXfI28lAaeZ+khV6NxbvZF5srZy1RRI7Jo1VslCb9EcsfT6CxZ+ikjgkBRs0XIlcEypdJv2NY+jijRDyyUiMU7jPoY23p0eo+HxV1b334B7weT+g6Oi9WHGoSicaKTm1GsUhv5JeOXRGK9j6tNYjEz5DiKJnjWBX18mHgqpHtwy2DpLIeJO5+3ugZqNrs3uefTUc062TgcilUvnhw7Ct92K"},
        {t="b64", d="XeAP9xGnrvVYTiLYTYPs46bzEI2/oY1ZC0N9MzCLS3ueC+ILMmyDiv8JTLueIDJ2Ls9tFhMguy557H0OBPpbGr50TEk5d5iS8oVkmKdwkaYOq/RNTtLODBb/sd6s6npjD4E4cK6hPFpbnRRlG5Pzz9YNy03FAikGs7GjPy6v5IWRxiWzbT6XUPmqLSACd0XzH4B2ijLTmqpmJwOaXjmTjVyCHbJADK1qkvNeQ1NmDdpX0FsqcBKjfkodPyaKVCNZxk09PidSmApQOAn9e7sMRW6YnkfLQpX6fjPzy/M6tHRc5TQ9iqF8hwxtxAyM3MqbjPu5UwT+2qh5E9STBYXQG8maAWiY+eSKGfMUl6ozUtCDBfY95TQG5kHVtuxVf0uudglHmHM35c82Kd0Q4hbHMhDInhvG53SU/+R5nFY6BwS/IfrEec+Paqya7g8jLN0+b23mLKdmnlIkQK7Aqqrv72fh+4IaoxTRK3TXU2NMrawkm9WEYc8Iw7pR+dT/DVPL"},
        {t="b64", d="/yLkqaJfukxcXOwkqFstbqyJ4MhWkx6UPKukj4WaJlpW0MgubpF99VvtWv/V0PYEOJDip/E3htfKBhJswBDUNnX/VYPs441L9oN5T+MjxwLEI0lyxemH5GYI9EnjqCaCT5ZN3KgdvGFbEvAn7FKfZnJsGQYNtYTbK39t6S0b0jaBkOQJvWhzyd2nqYPH7vO5lMjSTxrkDoL4qxxu3GsW/iBI7HW4OyFfc3O/vKXdg3jKYQW5mP3eiNoU8W3ClRyRGbYAyat6jITf9jtldGyoXw2TC6Auh/OHQhxV6BznWVfW+W3Xze9W4NaU9kH1DfP1dy1ZFXjJipYIqH8HzhtPjREZW64fx2Sl73ewIcfIK/J+gldctovZ08gBtPYr5iFyQHyWM6ZqEWzm+erLN09gIplt2YiSV7ObIIxaFqTd4nf+cvDw6N3Ck6p/XU1C9Jpt9pzeGr07l6Km24VtVFgc5pAvyuMy7vlpcrf0yCG0xtEM1NGr6XV1+qkqfpFvWs5K"},
        {t="b64", d="SByqDhdH4HDua13ib/ScVyb2L6ZN6xFdHf/qQNdohhMi87opQHPllWz4X8Sp7atcAIADvd1JNyibpkYv/H238tHp7GW28EPL9/GLrJQOgrLYv7z1DN6eD+GqQPR2NTlGBVDKM1tDRmiBZWeKZkkAjUlkRosz35oKW3G9Y5ibxW3tPROrGuWeRXpT6asF6nm6Bp7ZCkizcKogeOvQcajeKZweoydWnobkkmIzR6aplERy9BiVp1jNKSyvKgkfs8e6LVhLLJkmXoRyzsIv70CL4k1dHB6BWrD2NgXPTNkl8NR0V7RJXyyoYfqB6mWTSotDewPPw1qTTTFUGRLseMjoZeasaigQ9PQGw24G/KE5/FcKpJI16nqs69bU7nm4g4eZoSts+0ycpE7mH5c2mLoONTsUhwlLtHXts9lXWi3fsYT1eqbDDac/Iro8zHeLXDwxrGy11d+/TEZ0Ey+p87kl250iqmh0PdW6bbnU8Tivw0bJ4OQWvEhDAFMLRJe2h3MH"},
        {t="b64", d="i7mIS1D27F/nWILHiyToxps0fd//SNcRG21UtNTgVyCcstWChobb8oqkRX6Gj7geoJOhx95VNOBGb2+8W6E95bFslIZffGUEowNOic3QRcwIGswju81s2+4o5NfFtoJUYoXPzGic9yEwg9ixjfnrNFOxJBm9YG73ZJkgiDu74sq1Zp/bEWcuc72V08g5bijOS912AL8neQpfErsjInzbbxhSLQS2gATb0cD+VgOLv9gdTG83qlFfdusyzHKkyLV8yCz9BTyKN4qZShxLfEJtJh3bfq7TVF48ZpAIrSpRFy+VtyuauIfx+6VZYKFbwjznrKXi9THCabtPEXM7ndkX9qWdWoeBLV5SBxbp0ffwFZ2icXjjWHUjybr5zXHcuMMZCJ5iq178dZdRO0+vJjWx/wxqlOlayrV9lCrmpXp8u8OWVfLQgbFJrA8M/sz12LBSjRKcoZoxB8V6fPiQzgCrTtg+DJOPiDQ4TnCHA8SBGDILXj+Qnybm3xuzMJs29oyW"},
        {t="junk", d="7cc95a"},
        {t="b64", d="FOah199aNQMTcQfIAixs9Fe4Zz+n1nSa/ETzKllO6DzOoM8cfgDULN6xwMvFLaCUhlKSiS4BVyd9HjK/VB3JhV1QiOmcdUzSEMSnZf00yZmsw6RxtnexjXtrvxiT09iT3l29hLUPR55X1oWNVbWkA3XJ40cvf1tHee5WH/sLDvj762FWbSyGZfq4uoT/mfzOWqKaBkH3dP7YoFGSBNib8aKmBl/voH4T/UJyOwxowChbcJFe/qV2iJOib5xP6uJ1vwZMZZBVbu17VsMnhfAu96NP3MhLNWWVR5LNIaqnsJ0aKK3ISBgKquN0vogoXemovcc5NcLyooNFUpPirocQZ6s6aube89C+w5TIgHDqZHCAvQlAkgNbxObews2nt2785Mq2Z+Pe9pXlivjaQ9KUDqHnn+qfWnK/VQgGKkzzQ7X4SDYLJnyZ9EmxO30Shehzuz9t9rAG+rbaWWoyQypTsWWtJQe5C85hliIHxaRgPS4P8Ckzrsgm0WF7oiFYhQkC"},
        {t="junk", d="e01a"},
        {t="b64", d="kls/4mjXIBChAg3wegSQAVxotnrg2ORO1gqbTfqG688JQ6UKK678LB3fyagx82nc0yajvcPz4tuPfJOyJIAK5qTkyD4LQK7LrvI6mnjTKMK5VGcpaoeZJ3iPhE0Y7uKQtfJrGscj6Aw+DiEoRk6oCg2V75j86DE7/hzJNOHsf5Q0GsKCUYApaoBsvZHRTZQR93scGqh3Nv61KNU/JYbwxaXim2IIQiq1HpD6WFctzrO3b5ZNErsmo8Xe6HIpcUVNHjY17DGotybIIoSsnR0xlL5iOxoE38MISWBBwhpyWNH25NKzVAo1RwBZtx7LRTZhvsXgtzKM5GBkmsjwYlND+dsSOa0ADQx9rHTrSGtzRXRPowT3dBxisSvvlDC/OFoRWnsCYo3rR3dB+dNARACeRLc9ZoRTSy2MeKxioYNgzvSQqPuojO61dJwfTVQatQHzsf29dcFYR/b8wd1q95zdw70dh292GXxbOx7FClxIf0nGR1LJGLRqWIimWPfUXCOL"},
        {t="b64", d="5/5T1fblGEW7ZEBacaoQyitUuzTmuBPcnGIFkd5qlcpCDkh6Tu8ptm0cYd1de8aIHXlaWdr8zFbGnWVy2roPZP0dBmBjZ3nt5Ylc9vHbRIYe4IJX5shfvPX4nv7TIAVdA+6+j4M2EGgr/YzUD4MJ76jaHhnnEoMDuAbhpTkBXVwYfH16zWosMR9JymMyjx3pexswX00/Cjcp8UMwOBbVfZqU2VphG8irlHErVLc4BzCO4yDTkJLSdxAq2VBBi2n5q0BynFMTAs7xHd3K6SGErdzcLyNeWy3zm0okCbeZ21063PQFudfMGQUHnNqk9J8Z0PimppidMiPKMIeU7QZqXF96bm+mfwUpJ5iXo6HJ7l37E4ptFrW1l/f2L2fFnJQG0lgNevvzZ9LVw4p8fiUwSsY0oOvQT1v48uh50nvG3IgQHbnAOgprAtnf15SeMfXqCZRzaXfmnMQPJX2UAbjNTql1joEdU2elhUJdEbIDtjFOlSGNCpW7Ni40U/cRISxu"},
        {t="b64", d="3kqOucS80bLhlHl+TjqgkjSbG9wlcBKATXFsURZjmSG2y+BIGlmG8651EZMXCmT7p/aANPN5FTm+9iOwCunfc/iTwb4H8cSCEdCiUlqds76UrdzsCwiU/twcuMvFqxFuIySvaY6YBupO6YUUo6pdm/gZ9pbE7Oa7yUHJmtXKuQ7DbfTfY2SSDd5LXBEzEcQB3sStVrbUuEQ8fyBm9mPP9HS+gOh1zyGiG2cu1wN+RfJfwZld0m/R5O/CvC9zTLxX41Ns8+P+vNqffIx+p0/hvtusoxygKgvWMivSwfjyexgJ4jqg3GLGv/9V7YOo3tAOs78x7EhMrQLNLDhx3S5NmvFIoRicOeC5dnBKvkfnHHgCqRO/+bZ8SXgx07YadVVQBZgHlLh8pxyEabZOTlpISmRYYbeF9qdDyQHQmeKW4Um2FPSQOd1HCsXYdLjUHwDjCoFjjTqTpHtp4RbBCtbIRcKBx3RZXTOwYnk83L4LbER06vdYK7ZwY+X1D9X2Ckn0"},
        {t="b64", d="levB9DGp0MWt03O+XuOAkJqdg6IQW7VFRx1/8KjvIG8Al/42G243YO+7qJMdxe/QHm2Tg+F5Ybc//pMdDdZuW9umyNPYyopyWne94w0Rc8k6/D46PYaNxeg4uOeGrVQv6xBM6IS64+m51G4Dzt2Ein9Zq7iGsQkVw2dcNBGARIVazc+BOqSEZ1a/0q/rhRCccZsoEK/vX+wHlV6GJoawIRaGuhmjh2PZ19TkLV+JQHvVSOejGo1DpO25M2C6WQ8pJHrvFZKEPazv/7Kc0SInQjcSwT53803yZRCVWx58W5QZ/A6iK3gIrDCRtWxKZMU0GbDSwM9U7N+vM126un5pFoI3HzzP2/8zxJovtI/NwbNeOTWliYBFKkeJnQR2oRaPVA5aP8crKUrW4LyBHadh/WNXPFojfS6luuU8DzEgI92JcfLBYmXwEAC7IUOaxyOsPYlMbjZ1sMKxENQZg17tkcRYIUJ2uv54AI62gCqjIR7DYPmErRC2030yD7GlFA7t"},
        {t="b64", d="VT72gLGZg+ljuv/4tvA3+Oqbcm5rHQevWRnX/wW0FjLTacpCpGQ9jj8ve0DRwOHmdSusNw3Dcx+YP33CLNntqns+epzzBA6+dXg7ql4r6lJ0TB3urC3RR8n9DffcLEblUrKQ8ffb0OwJzYg+PKnLdm4/quKHvdWDKtQ2ZTltb9ngB1J6ax/nNNwcZKBUnE/oGMFumtASzDmPRtM3K4jxkSXW36bKbQaRMSjmtIjIe5ccyxPrx24HfSvCZJmhsywyXmn9NZy1/hqfJ25uSS2Ut6mFFTmGupdhC5S0oYVLq4bjUQ6yjFNv5F8vHityKIpDvPxR7+xoFH6kpPV3VGbuc6UHx8c8LjVDEVaRUa8YCKIFw2JK+rS9j9Qqw8FPl98lxWHavAPRxu9apnp6WN1ieM0m1ADX3Y1gfViFamkIFxiMJ0/PnL+pQ4dYh81SBOXQ/APkVJWwPYp4XmeQkBDOuXu2o/m5w7tAdlSzI65jUE4YLZRH0W+A73RvMzmr718I"},
        {t="b64", d="rCTKVGua+EVUmTt9SzRjOw/6nyywiEIVjuIQGNosvHc2hmWNqJRMKOQ90vLdbhG8ni8pwsNi2LUa5GB4xX1eyUubPRs2AfSdz5ct2DTZsRAj11C0++Vb0mLndmzmrdaXkFWXueL7nw4yotPRzAI9r53dHLk9yLn9Invc1W5dUqUA3EFj8K7I/h4nNevxVIZfDq8Y0edie7uQFiwSTIQeQRT/eseLbo76SPdMfH4MRcPGg6QcnbsHYW0tFtc8PVqOJrZZfscb/Os+Ydc44kiK0PAhdZa5kKr6fR2nSSl/rLaiuzdI72jVoXSIn2+a3/+UQGd42/FNCKjvzAtHm//RQXXVF4BRtVzIYJ6PiiKcAhDoNhOZo092yz05nrdvZuIsQhyAmmGFRlu7E/WHUiI3o3dl7d1PwIRXSaRBu01e7mD51/C9W7pW4MdiYN0o4xoI5LZcevZHiBVYM371ID15WB2CHHW9F+FVmXsmySfr0g0d+uR9UaAzmWwq41su7BHl"},
        {t="junk", d="de25"},
        {t="b64", d="bCHzsVopTVhB/aLlQLtmk1pjZSt9090IU2TM3DW9noX+0Iicn4fDjuACvFYsJt1/KdbUTHd2VzQyCA9Vwjrwm/QtGVvLxPagi8s5k4Pa228vPcJBQdbz1dsMhhVQgFU0smllxgrt3c2PMrGRkKDPu+fG9T7eBWtxCav+CiY1IAqN7Do8G/rtpWseRZEvAodTHYCNXLuNDdgvEb8BuI/LDCcNJHH+Oie0e6AVw7mwjJ4eWk0wZaCZW0XbzNovTHkg7tYWwOncVewWs+aFGM5GsIiRjR8YJYct1MnjQJCgdrv2qLjQh/9BNRLshgLWHaLZoCMolmNoIcwVEsYKVHMWHNJAv9EumBu+JGhDGQk70sURZJsBGgbZZ5WIORmhuplt/TqUjIcLrE4mL4qUJvX4V2uw3DoUbDuStCqZQubzAqAHfc9P+40EAe/4mpNFNygajcTVdVCGONhMEA/ZagiGiCSTLCPdOoTjTQNRjKMEFjEpIDRXwTjJjCkAFw2vgfar"},
        {t="b64", d="OZwlC0XEuGIUh/3eUlvUGbHTL/Gj4TMHASHQBYfizkY5vhP2XrF6d4c9vlHQ/oL5kMCS5lBKs5BIzH4BauUi8Y1IsEuNXq7Zsg2lEu5Zl4eNzN6HdrxNvGzoRgvFGbydWXQl9urc/6TGGlhGRRezT7cpV1ftOQez8mf8NXAST9MR8JePFSEdLkGgV0UxyFP03VgbpfOI/oa/TdeqdNXkgfYFZZcHlesf7sc7TXwdIbNR2oEjT1i1ugh1j/F4szwji1f+NWUiHUXyVOQkMwsG9ombMldICtsCAX4nqBGjRwI7bMZ38bjbWc6SonP5nUMvYpWF5qfKqNl9p9UOuVlRRIzg9r6Rd4FcgkLPTzGYdTxWMZ5pvUh9HYRLI8Gw2/t+w4PXVdpPyrlpmybBqhBW1HsnZuLgak8ODKpjxssCeb0QHfVJfFmVp1lQwWvYjz/3wELinR/5oc5+roIB9uZIAeT7dHiUHrjrd5ASgwYbaV2yGWnJ60d2rCNJBO6+I3EZ"},
        {t="junk", d="ff266e"},
        {t="b64", d="exzD6+YwDQLKVIBouxY1OdZDzVuwBzvTIC4rPVL9yXddNSXhDuofUYmrq3iLNjghZwltTop9qRZgNLlHVPgwbfr08/twPFF+MtZIjcItau3cK4xorRbzjVX43oTeIwtR/X8+zxZNB7WhoqgQMfnGMweSjETa+XMW0ki5IVwViP4J1smrZswOZt9RUTfoEFinLo5bWMHLiIVCC6OpsGjOC5N9+7AF3ftv2iC9148zzvd0xLwzpESTLmuMv/3kBerEKYoKwkqGNDXX8qtnWLPD4NwXP7GgMq6ZCtGFiuO0BpR0EAtQICsH7RyD6rWreIOY2tirwFCcVIsmeCnIsO8QWbKa4od8/Z1Mr3RIo9caQk7CPZW2nk3Nn3XytJdZFWwrHl3Ub2Ppi7DXJ6xgODoDnpVKukXgu2AuWeIBWamd8kFLFukeAd1vsrKINSrNiMABe+Mqx/bB5f5K4hn9lAJmUlY4ceeKs6tnMFJxxJexNOpy/FE94yqeiBTeiy171aqj"},
        {t="b64", d="10lRbLSLyLLoWkUN9RGJqzAMI6BSDFgyvQe1QChAe92t42JEvPw1pjCjQTt+db75iWhoQ4kLZd8xHCqGrxPni7/XlhRDS2e4hRAsfsh6uFAF1MPMTU4ADYHAc2+OLUgDLq37duPl4poMSipiL/QUArSyHjZLd9dZ4zEOsNXoIp7oiYGHEHYtDHnG3EniBkggG+9whDl6lHWFTG8DtZNKHP/5HyiWusEqcGCsUZTiteU8Sp9Km+4HDaCFrqNHkKXSnCO9Mj1osWSiEeqE71lRtV9Z4HGlNvVZcD8h4nq24XZWou1Zb3VYXnyBAOWSMij10qq2wVSO2A/LoGMq25uxqv8+XXbPiVKM8/OLWZaOiSgYzWiCNdR8/8Al/u9G6K/GMeyAgpXG4arBxshGfcj5xXWOX7nqgvdxH8WClZsKhmVJ2MLyc3bnMuNx00Rh1qy6/zEVa/xo63SdHPIxDoqFWuaxhH7vpE080vjHnwCKJF4+lCI3Ce9QKFca+jzsfhDl"},
        {t="b64", d="Tgo4Ksg7M9twunZkGGf9SODJanCp7nuKhXF/PuvzfJqrrNBrDG1w7prnp73O8QbJ/Y3NN+ndFqvKUgd5zBDG5JaZWy7houdtdgKEB2gF1v84Y61yx7lNe3QPELMEWighQi1YptAXp8eYb9hv/cMYyUIiWPB5BvLgTMFxKybfWvkTEOmv5KclbR38xCNWlXTHWHMevYqTXKWdCm03UC0UCmOu/+oG70A6X6S3Md0O2pXnOcEX1LxsggXyVRy4mo3VUynSnjna0Jm6wNEvQbwaSy1nETWu8R2/ZTKDLGqZQXs+Nol30ZlkjyU4h08ClMiUv1sfSgyCvu7PheOoGXL9xX2ng/CkSqZmqLYesVRksgGgtukmI+SsIFMLBjBF+6uXXnPVS8ZsQIVELkTZs8iZQcOtI7dhuZD1dT/ZzpUvUClFydgTza1/kdI+Jarc+NvbUts62/JUpGsPq5Ybb5S3w3ExL/oSNc/59gN8junBAkrXU1SueF0ikrAn0CwJ+Reg"},
        {t="b64", d="g3VaIaStRPDSwLMHR4x2WxxxuGno9oWrWMaNtkbOMWhlO01aUxAT7HbJc1iWdrjhicQ8Q2lC4bc6EPYBE8KcuIniE8MDGV2liHjpbuZcjNWkJBa3tSa6w2wWGq2pgTh+fKpRfWEl6Aafja7uZ6q/+ScLgbLwbBZE2MrADaG5tdWIu9gJfuFHiYbO373O7/VRt+NQVqY1tJh+gOYQwas1iZkYD2vmX4lERn1vqH1scz78sg4Sndsv94p9ysYK9d9khy1XfZYxfklpQqzYprZ0lnh8XIgkaGBIH559NJ4affk6F/36wPmoCsV1t/P2gmhkFcd7rtmgCagXJCc6Gfz+mGet87K1zJA9U2Ag8IP1k7LMhbv/t35tkybUOmG8ykatmgXsdc4jum5hojuJurG0nwNdiO3vO3HjeQSPUMNWQoiGsIiYSvmchui2qLLGIcUzR51tLuMmAE8OGzFzoY2OEPTHY6w742kycBX7aTlOKelIOhjsNIayPpyE2sn81XyG"},
        {t="b64", d="6wdkdXTNEe/Cb47HC13V6Fkav5Gzzrp2rRvugeKEO24sPTRg4Yy/C2SycKExNh1iSjfQeX1TW1z+uOYEsac6v45yGkNJfNPCKg93OrPUQmRpk+WjXs5S5J4ixO0DP5rXPy7PPGc3g4EwKrLN5kk/pF79Ha34Pi9AoKVsNPRm47FNCr5ebvR8NiUXyWhozHhsJ0f7s3ih/MxXVqPo+LLrWdgnupD2rOlbDbajt4PctAdddfssSbqhE4mXSYDWRnXJpOfudPIXeIAQPHBKehnTDBaiKthJNBoyhBZiCtGQCCJI9t565LVvuK4s+v84ceiUzg/IkE3+yJU+ehDWSmzopPC/IlOD5q0iLW/Jv5ebjSA3/movRMA3n1G76/4sMBJXGjtn/QKvWhr0opeSxtJUKYoDSeC7BUwfMW+XL+XXjO1fRNH1oOdqXnxfy2Pjxu48QnS93nwpPFEiED7GatwH3tou86PIKwGhdzQq5Z9DGVs3TKM22zN2ROmH5kAtxEZq"},
        {t="b64", d="weHeAGWLhVYwXNJl2bQckhMGsojFC+ABEU9Kr1/Zvi6vQHXHbwVqmQIwCkWTKHO1zYDff/SWO0/BfKRsw1Sh0CXKelWmK6RIUNx75ubisEzRvaJpEYQOPdFau7oItCRgumLQg5AiKk9Vl28wyQXBFjgP35CAu4oc4vPxtmtQxkAiDbEm0bdiEMCL5X3evlaMcTY4enrRnH8xTN1OV2uBXwIzsDTkDijKvf/BlnkKzsUQOW+tk51Wy20mXcvwR8VzhZeVPG6ZBpa8R5YFQfzEGlO+ObKOL3hWTGQn3B659FVv9MrZuaTQu3qHUUmCCSAv1FdT+wkCvx6sOF/Zd62TVQIV3enJOf2+3Zw6VrEMrGMaQpBMQJ5pCxnwaVOxzTZSLj+jrC9ljRqvFQ1jHjZSo0LCNiRy21ZRhF+XHGGTDg13Hc/BhaXGWT2Uht6FcsgAJ+8GhbmIO69bVUibSDjHjaro+OTE/aQyV/r9p9mlTW1gnu4AQ3YRmLl7t9rjUJO0"},
        {t="b64", d="D7UNTQDWDPxei8QUWugISyoWGbNppduBg+LEDcs9jcMzWKcu6meb9C/cVPvgl9pcgVP4YhmK0s3t3ud+jVcH6+hdELbAFZ55SfDzNGa9ELSWADg6lspSOU3BnwgqT8MPOkD77zaHcCg9mmXHPdIP4Qgb1NJQxdAikDOi2Y6OT9k/0jEeGfqvVfVJI/TMUgbCGA+vVq1tZOpHFhDGXWcFd20zemu74syjxR0UJIMX3PM2VlR1cLOeiP7fH0CCgdzpf35YYn/EGJnX7g131uHbb1Lxa3V16Dg0096+a3+sEvCSuXT8+HBuQLN7PyBgpFvszhEYDUcuvRwo62j076ESuduHi3kloXLrY2q+66xbsSvhoj/q6JXj0RZHudpao/1Ncy5HMRaV7RGfKJD4ojzaiWQLeG8qXm6ww+lm3JjLTeMEOk6YvDP9Nq/z0XGcSvI5mWFrh2n2qTHaGozOLpEKbD84JffSQJbrd8/7vt3Gdff2hQDFnJIO14IBo7DyRWPH"},
        {t="b64", d="XvjUk7u1zFe9ZbfZvM1nBr+gBMi3UzdObQvuZ+iIaNpb7ih33J7DYZANW5+Uyg2/SoYgm70ff0+mPrcZw/AnfsmYWpznjY1jQ5HpbW/I/zsnPQuNLR0IUGJCk2qpNKatRAyx7zv43JxYa+06FbO9Mwy8T/VKeIZRykQHW8X0dHoA17ovv7MJRaIOMDDXcB7kvPnaNMYMHWyKYfu9Xq205EaKIfAUXaRU3CY3sBLMv4y94QkYtGW8CeGYT8Z2XIFpPpxefT9QjrGRXohIGNkHnQ6TPpO8Qu9rf5OR/OGpkSr2MGbwyhYKv9dlj2irTi7jtoHXolzIJr0M5q8OnFF5x76ScVNSEnfwz4w/WHnNukBe9wS5hgw7WT4nihylnprgcbz+8ji1iTWOFs0JVcohUBW9WfXMo1iZ9Lvt1JevBskuCKRVqE2uQEGbjOzhZn2vKuBZR+JfFicCuDIq+pWojYsrhmcTjRU3IWaha3twY3BU1PsJZp40P2DUXqX4lrwV"},
        {t="junk", d="3985"},
        {t="b64", d="nIWCHTRHx/IkLzAaSWjlCFZ39DNoTzC3wwwnl7qsUFa0KUQGFQhjuq88Eo0xiitw9iZ9OXkUZMVbulefvkEIsQY6q3xgPQWJ/Rqd7lJKuZvClTqTtVBJELqlh54vZrYpg1Q0OcEGLGM5bEKBeO1uoN0e5dy+ubSNaBYFdq623QBl11e7Jkcbdet/yn2aUb1YFqnXCmffE7Cx501oRdIqh2FC+WbzG2t2g2oyiUGYcunDeFnYSN09CNeDU2ZELKWZDj/2ABMf9UL254o3Inkw0nmwtQF33MkmkQy8+1hRPmSp8MoG2JbqD1eV7+cCe5Nd6sw6Dv7M7EZZtKuMMkSys4F/SD3ai+446s6TGZfiCUl2wei06STHNt/YndfehaqUtjBe6kLfowvzzOq09akihXEPfdj1abBN+l3RNAatZK/9pgifUERB/jX/iEZ1qRWPAlyDPRDSLuI9rxKmt/NGbKqRE8j/9IqfVhYp3sdMqmUHUrSqy0S2XuYvdsyKA7Sl"},
        {t="b64", d="8Dp3213nwEe19tOEjgeoHLTS5uRulZG2gL8ar7xoepPeLTQ5OehXO0qagCEFL9cF72yhIZvSnaZJrIPeGt4RXKLsLAxIlHyD6UeBzg+0Qb8t1vMTeKzeozu1xDrkTSnZ6Y9B+nxjoK2GtkWEjWq4jig5yfXq954GVapdnHAyBg9wjAZe5pXDEXLL3RV5DQNwUflT5OzxyAPw3spJYUeeNtH9L8Kq1UcQKQ/e95k6M1+znKN4xTVfhssxegLkFzvKF2YcxeMKE1Ng986ol+VctWon658hR3k4OWNXeyk99EqwnuCOFRG7V5blXgZf5DTirSZ6YiWGscW+RkzT7b2kYzFYWlY+I2WZ8MSKKNhjFO76SVaG8lG4yTWbV3izET/xvi0b1YPUpSVhDfBoBTB0srB4Decg5+Iv7OkVXy7agxcctJgXZma4M+yoxve3LMv8F5sUIv0/fBm7/0VXyYmHfkwJWcdHHorK1hWuKJhlYRpHzWTrvfuh3YfqHhiyVqKW"},
        {t="b64", d="02WOdiaEHO9zSN2VyeTjpyuLH6aUJHcUEg+sbMVbR3ShHlieNwUdnLePp/06UQDyDKW811ntDWbEZjNWS1YXHA=="}
}

local function rebuild_cipher_hex()
    local acc = {}
    for i = 1, #cipher_fragments do
        local f = cipher_fragments[i]
        if f.t == "junk" then
            -- ignore dummy
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
assert(#IV_HEX == 32, "IV hex must be 32 chars")
assert(#CIPHER_HEX % 32 == 0, "Cipher hex length must be multiple of 32")

-- Hex to bytes
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

-- Inline AES-256-CBC decryptor (Luau/bit32)
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

-- Decrypt + execute with debug
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

-- Scrub sensitive values
AES_KEY_HEX, IV_HEX, CIPHER_HEX, plain = nil, nil, nil, nil
