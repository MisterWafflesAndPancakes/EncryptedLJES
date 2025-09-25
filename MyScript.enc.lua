local fragments = {
        {t="hexchars", d={"a","8","3","0","1","4"}},
        {t="b64", d="NGa2"},
        {t="hex", d="679ef00e"},
        {t="hexchars", d={"3","c","9","d","3","b"}},
        {t="b64", d="Vzg="},
        {t="junk", d="ed8a"},
        {t="hex", d="b9"},
        {t="hexchars", d={"9","5","b","0"}},
        {t="junk", d="0216c7"},
        {t="hexchars", d={"1","0","1","1"}},
        {t="junk", d="dd01c3"},
        {t="hex", d="5ff616"},
        {t="bytes", d={176,84}},
        {t="junk", d="b710"},
        {t="hex", d="94"},
        {t="hex", d="7c"},
        {t="junk", d="9257"},
        {t="hexchars", d={"4","d","5","0"}},
        {t="b64", d="ga0="},
        {t="bytes", d={133}},
        {t="junk", d="95f729"}
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
        if f.t == "junk" then

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

local iv_fragments = {
        {t="hexchars", d={"8","6"}},
        {t="bytes", d={248,228}},
        {t="b64", d="MIw="},
        {t="b64", d="kw=="},
        {t="bytes", d={23}},
        {t="junk", d="452f35"},
        {t="b64", d="fA=="},
        {t="b64", d="0J0oKw=="},
        {t="bytes", d={129}},
        {t="b64", d="jX+O"}
}

local function rebuild_iv_hex()
    local acc = {}
    for i = 1, #iv_fragments do
        local f = iv_fragments[i]
        if f.t == "junk" then

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

assert(#AES_KEY_HEX == 64, "Bad key length: "..#AES_KEY_HEX)
assert(#IV_HEX == 32, "Bad IV length: "..#IV_HEX)

local cipher_fragments = {
        {t="b64", d="K+wrUNcAnA8iGWCTreGVwQdPhTLDGJbF0tgCZDLDqrUx/EWLSHthmiEn0rWVpYKokJAT/clUg3BhpPDLa6lBU0CjzF5Z7RsHEQOlAgDSVp+bK0Rr5yo41YiOAJabWQYwCgkWRVznI+jhgIAUcJ0Y2SQ5LdCNOMmk7ParE0bg1VImk25K9/wGpx1VsWjMwLhbkYbowAkCoSxhY+ts4iyfa+weixIA3uVrwD/XfZiHqds9fYI4SaGX1YgDllbSuL2PcDzcm1Op3hjBx6tbQaC3AXR1FK+l0be1TA8FhU5n+XoRi4U4yKXEpzYd9oZ/+yi3YWSun3Arhf2yFeG96zDIyWjbuKp0OqRCD5oY+MU2JT4nq4pbFYLsOq/2IqDKwU8AYZt5L3Fvqr2sEahI15TzbTwmCyL94owgQFvUMPikBSYbAfYd+vus8r6IYSIAT2CP/vTyqKuIru1/zMbahYCTk5XNIyXd+npp6AS3BC6GJjuhzIyy/rdVwvGzLXia+kWm"},
        {t="junk", d="52d1"},
        {t="b64", d="vqeH82+H9Lk0q3gZJj/4c1tOGpw4jJkpmwokZ/m/KA+ZEc0vsOOrpik0vAuE+M16C/1R86qUsiQm6idRIeMmFsQs5xEhF5Bn/ivobgjiuI948fCWP5l2B7Z04wFG0s/kuyW4LBoblBPsJT0f3qqp8AzjYQU9Zp7PSsIZS8SM0dhQzXJFoG80pYDIzy0hFVj9qX5gjXfRPUe1bgCeDRDAeccu/l+BXFpmFMzqrqYgZsN5zGSDxSB8M1DRrR3ZEPzt3I0feUZ2Iursf2ac8MHolfYndsbjA1Ll7tFVG8nd/yOE1gmjToi1WZu6cQ84H+eb+hFJv0FdE30TfRdmyihbPtfyqf4dK/dInSIGcOEDnpfya/qo1QPoKYwvWDzqzexbnYi5iTaNzpYqODGRaNhJ27cZWiNkd7bzgE5rKBJ5EHEGT/Ipkxt3w0Iakkq16El0L2I2WdJjfJGKahd3Hp58yXKofVJSZLUefbMcW3zaHNQ/IqbAl/Qp6n8EgB+Daphs"},
        {t="b64", d="sNmQ7Lwq6X6x333jsvgIek0kAz0lpXOACWAsmH7p7LlINZXyF2NUw+MZ/4qhixiWPSk7MAmUpNeK4WmrCHoxw/YKAFEgpFUm9ZKydVvzNrTemMlIEfBszoyUHynL2YbummTSRDaly3AG/ach5SclRwz6/w2BP/CIQBidm+3z/KT7Ug/DTFd6aOtUbM8xahrj1qjnTBFNAFpw1Pd/QOtwa9LnBWd3IYBmUMb2sqbn+FDOTGg0/dE5E/dPD8Sh/CYLPQ20DHSa/5Fr/2GiH6v0ocp2stc0EEoPAyfaR9IIFVcTdU1I8q/OPbx4N8j6uzMEnMZeRLDIxd4wWhfs9MAfbF2NishD29bCLhYxN+b37CBJA8KkGDRNIa9rVq/P0WDZiTHo5WayeEd2lvC77Na4h6w7WcooFgAEJEtqB5sfqmYrcPqeQkEpOGh7EFJ0gLCm44c+/3cV44hLwj2vzf989E4jqW9kKpM7b6hUaiVlo+BLX+d2ujq3dQYDcLYEOBqy"},
        {t="b64", d="1o8AUcI7vrtBZRvBxOvo+Lj/9JLgT/YVhW3eqwYS1YdmNGh2hcGlkHSwZaORzSM2IpVA4LsksWiEuaMBTBeDD3LA73YtK8MuQHp7upNlUQRDlcAJfdtI1e4jx1HeC508T2wnQ1fZMxwgXH1s0t04qEPIdYUgyv9C0lWkxCKQuCn5tQBs5xWBTPoAGJH2UrAvaC2j/E/Ut9LRYK83FU2vxseatZktaiLO6opWivUCCTfpWL3wrDdRFiyLKVAx97W4FQrQEwjnAtoD2vo78F0bRxJePwPcaD5t7VVWLEJQyBttY+uvIPlFjTiNnz1GozyigFZx7YPmu1Vprdsjmddf36rGzZbySCblJ1OkUckUtVuUc7CUhGsDoxRDLG1+afIQRp5S7qI9aGkTImFwNtoq1NVedMmZEOp37/iv8Kx9s5r5R0WXp3/mlIjWtnhtxeKbBdRF0rQhQNA0tukWp/TWXca761kkNG2spi7R3SAyTfp/UIrofO891hgy0KCXcY/o"},
        {t="b64", d="w43CcqoWjL5ObzppGdDxgeQjLYD6OB4tRILkpNjCdR3dSFKazirLFoKk8Mt3T852JBV2rADly94ORhFfXFWwmFsvMHHjvGRchnqyK0ccZBB97IKfVgzQ1PmcRNvXcbj0SbjxrRWE3stlq2Ev+1M8xrbB5PHFkpg0iPNG+GhjFFyPUMm1DTa58Saf+wEKp1gudC1S2suLmdXj3IZxSRAzXge7Xr8r/RrNqipybVs/na5PWn5Yc+qymBRw3nnUkLpsugCRniK5j8OdeJGGcODPvBKI4uE9Y9riWEEiS6R1PEhTsyV6+dIdtFHimr1IdqtL3t83X5XQhRMqIzVFqQXfV+BXcOFTQqj1itNWsDD1Bk7u7TlusZdNv7HcP6IbS9iAF3S/50cMp8Ll0y60CgUpqrdsvI+O6eiPsI1MEOiVF43JsiWOascC1OGPxew2rle34Mca4G0Ax0hhrAc7PN9WV1UyycuW2kr9JFQ3X4FFm6GIEpD1+C6WQYniJeqJUd7k"},
        {t="b64", d="zAYI8oak0bzrOP5VPJLmNvTiCKT47aE2cQ2c4ItsGFSLfAdCW9qQnwn434C/jWwRTLHAtX1aJVQg/UTFRn66qIMEH1QaglRFDkWdvKkZyurufq2x/jBdkSgrKjY493K/G69Yosbo+aZqrJKU280IZ6GJWjauaNVxTSKWU9+rtTYMSOTWqzCdgkBhqD17VZTtphY4q6CytD2MXZbRjPHQ0EVeYUJa9inDzX6jZk3d6ff0yw+lGHp0O0jGjDXOSIS+WXC3Ez/p972uCgMGfvACINRHVt0nenc0I0PZdrVZWLAg4+TWzIoo/w7Fgdlm7NKBd6LuOwtB2v7nr49MnQSXzrWiE8b6ZpbvfaACba+6wOjct7G+ejIaoVDeWSK4ppPepzhdm38ngDG/GxSeWkh3j1eZ5mg4WV1cJSs4QjPybV3qD013+iij8dZZzbUVNIQWJaCZ+feMdqzutnyGTrq8IdyGkQhmIR2Rl3k8JvS6ZjJxPZlh1WjrkanWC6IUclak"},
        {t="b64", d="FIBe+eolOVV2w+fQIhgK9EsyMwSBNeUjy9l4I9GOb3tdCgqdTRxlkF57+VPGa2n54NMSTxmW881iPmUbUH+FcGYGaxwZv0r/WhdEFFhDbHuaAJ05HDRJXX1+905Fy7LSfCi8G75yXVwl9jA3+J2807ILwxqkDzflO5Dd4qZndfEtVP1MKUQK8X6oLT7B1W6TWecBLeP9b6wC3HE3wIO9WZ880C6H2uoydKM7W6ctB9gBpjQ7R5Zn+TfWGf9yphHiGnZ6Cf+JWI0A9bNE8HFa327k6qVsuP859C/4BEWVWFhN8lzOnP6rVveyBxSEvTA7VUWLfrncAxumR/AK0DosL2z0xbFSYj/SSH5mIbZFO3mtUoc6+zQLFh4rh07xNIZpS0jRDZSV9MC00BsvNsCnzxyQLMhDIdcziU/X7Tn1PveJ9nZokeYMLKLusFlKCQX5z+sBwyVNFIdsEAz4WN7A9dL9tTuNtdoWBTssOlEYYQJQhZSzjZCDB/skxgE3zdJI"},
        {t="b64", d="IG2lW300+sr0sHwV2VpkSWCQfkb9glgisAL0elBfj9rZU0DQDJ4cECE3o1mcUr7fZVQh6rUsJ6VEgqZ8HgI6NCj9/K25xYKLb+f0CTCvVy7V6y7vqpO+HZQMLEoX5MHewszwansK37qKgPcALk9KPz27vAcVnnMpBX17K55Nsqj8mSiH+wGFunXtKNs4w+2JGYwB+vtbYLBWEMggcCBsYjNdhl9DInZX+C0J29Ni272dXAohoVbOqKQZ8MumzcZXEQCq1TDdSFN5gxMvlqeQ+NpCNEr56fzcE9FqH8gsJBtTNMwtRwM3Ph1EsGYmH9NfWVIUvu8GuobTU4DGab+/p33ms+kWw66LOzHI/Ua2gyaRkA1WCV8Y5GYTkBuMFECT0lsJIUi6/ytRJ1T3DnZd8VcMrjyONIlRvL6gTUkVvMt1AN+4bjH3qXTLcSPLIrlGi/VRqkb4Fu6zcL6dJClK8EBMRHeCF6L1mLz6Xwa/zA8NbtIceCLhBlGrUYWYJ7rt"},
        {t="b64", d="QmXoooDMTtmOJeFq9aiKVJgQOap7c/E2TE+z78mKI9d9qU+yv7owtvG6Lx+bp8KSmA0YPN++liqVw5eK3VS0O77FdQA/53c/zAdnxL2GaZId0Y1UOKaKzX3Nt9nTlx98eZDMocoR9IqcOgzmemAJsGQLnum6D8OxeeXTNg0ZkKCxz0pm52OkgZxii7fykSM2D3xcFwu3dv0cz1wdCqr5zrX1KAqUNKjSvtWsqeqz8l2ufBIBysXtbuKIa6zrt2B9Mtd15PH3uBQ1wfAo5nOilBpaHiKCKAwNlY4M2JWDw/9PoS78Xf9JCZfDOTuAjdzZ6klioF0AFOJCxRpIPT86kxgIjxFdEh2TLcdTSFkky0f+lG5apYF9JE1UuFdJO5Hs8wC1wUgL5uN4zKxG1kNjHR0/2Q8Sj4Ef7ol1EqbvCyumlbqBsWbH2vyE4q0PRbf29xY+wzljaO2WCL3HsGJffQBH/WA4eiAJe+dGDYYmfFszq44jichtafVyXr5RP3oq"},
        {t="b64", d="lAXzaaSJIhL7EUVvksXErQBVhOYqXyAIXrwRAE8BCabEK91o6KXUzGQCm3ab/y84nDF2qZVh5WXgx04Q5sl7/yRI2Stoe9TpsK1QZ9reRMJ3JLZWBxEU98SPnIqZJzuLnjRlWd4TtCjJh3hfPdypGBUsqoUGFymmgPzDA2jpETqySWgq/qMtXNJR/wI8q0E52L0ceB0SxpMk9YnoPG0DTr9C5y2MSNcYTGlyEzOzCfilLGb+PEyWzW4v8KC4xUeekGEmZkdOWxZ6f5H16qDMsz0cukOv+ynAUmtO33ZM+sUyU6Ep5srUFf2Q9I9M4yEfzeydAJpX93F06nYHi7LUzrl77yDPNrteLyCspCcr3k+obdZ3FWkSKygBhGHVaJwJNZwvozlvAgIazMMWNtM+YIMxYIQ+MRXWm1RL1MdBK/3OY6s6r5388bxygH09l/aKxIZU6pKpSEZOJlUSPk2bgrG4BNEStLQfl2LCCyBfJ3lK5purcILr6glgtzMLuITg"},
        {t="b64", d="I/xxOa4JBNKapqbWfmoq1EC7nzxUD/uHY+IudchBFR8w4to4rxiIvSMM7wDCEOnGPPYMb8hN5JRoh/067mlKN1M/Vx9dojo3+hHNVwIU7VdAQ2c9UcZJ88Si8pbqfJgI0JuHYcP4LwMzqj6GmlORzg8E1mH6kXoq2/z7iIQAoxgksEKszz58RlSuTXsSg/FSiOloGQQAwqeqG5bgJcGZ7Miu0WLGUbtSbKJHXeVkYnRWoAiKxYB7lgiRSW9wrManZOdYuJTkW5ytwwVIMqlWyMhxrvhimgOV0FtLc3a+Q3FwaPx3PscQnqi49/x886EDo093sgJptSLwfXkaV3Aotk+S3INFqPPGYXYLSCbHPPhcS22uOv2vNhkFis5we31S8BeXprRHffOayAiwfRzTGWkq4r/l/bsrGZnXzpx6I3edpmfwjOGjLxhkKiQ0FJEGuwA+VZO4NuLMYIQb1ghSgJcuiWVKuu66Jvp4bFPx+/kM4BBtnQhCy5/13y90hn1b"},
        {t="b64", d="+tq3Raa5sWonPrbyu6RtP4I/8yjZoGxEOjgol7jbjFXJVxWtzdvUAWNSjUCJZk+a+VTMocXSYzAUgJk49OUUWXSWS5NMYusy+hwVGQ6hTxtvcyd3alBg9PrOLBLH2sSch3LQAz07u4+8QaDgOhPNFTZQJqmTKiSUy5OnKvV7FbTbyO+gA8w0P042Yq+XygVyws35VdR3ZkOmLkitncysYZrBN6vWdS71h/DMpNp4nC7mKs2dkMauJDeGmSYFwl7nZG7GU/X0PAWze3MY6s9WdnMdeYfLD03scR3fI1tMe/pxF/cLMoqGj2kaiiEnoFp4yKQyYaixukq18nLGYZd1+WiP0DoheANXuVVJHDp+2Yhp8Ft6Y2yZcm7mFWVvdH4PpWaNZpgALLmRcQWTdjdYBYu75Zoioscvi3HQ3OHHFoW7U8LDkYGI9NObr3HpToKugksxoStcsw6nFEUv0FGhHEoFCogYnDLj0x6bL9z8DNu15kxCv4vArKjeHG+5yad0"},
        {t="junk", d="d7005f09"},
        {t="b64", d="MKwMBZ46ruc2crdA4oGwPijY/M+0eE77XHmgOdr4BMeWJ7O/2MHp1o36PqllARBMxBd1Pysbxv3tgSKrFE7DkQRFoI0GZPC5jzd3FGplaToT8J2eurti/7hMOse9adv8M0NOkkCvRxxKdLlBSTIkNdiIl/lHYSD/y26Ifk2JdZa2vUFR/jeQGzmcmH7Qc8TFo/cdF9j60kK6pg3iPCoVyLmzuP8XJhTKrdM1n8WIEbv13OMOlUkklIiJDT4A0LzW46vaPMIfxU0sIl0gHvF8htnBZPU6ganrVDPfKCVu7ouazexDLl9mZDzfWTjzkBLDpBEmCZWvQ3YxNaJtzGpZGXDkaecqsH4ZteoOr47vkjwVkhlTwsPMrCuhx1qp+5g2RuKHtHWjFVq+nlyon9Kia21joM1nEQF2rgdY34tEpFEHL0lWACqu+lbheChvhHkHakWfMM+QzrS86uWYVNDBftflmakDIGAKMIPRKpuxzLD0BbmBHOHOLEaNeMXbtBk2"},
        {t="b64", d="3k9QLJ7w5vlF2z6Txz98YkCbzMiulfmnig3kuqpSirKIGyiVArFpOB0sjQIFkp/aNs7STnNBGURsS8vDzkVJtekft4jRfTRnh2b+fixAaFWY28eW2R+vt4PCoO0OUX1nrbMVJembDjfwbzWbRkaeGLLcmOEYGmAcGwtIk4IEOHWDXyzMLyQB8+yBxxrPxuRsYMcG1lCkyN22XlrOkH+kziS1pywBEmiO4mnV+foYWx4feBL/IAyR1Wk8CiRdOaK4EhyHSyaFE2yfQBqf4PXk7UmJyqO1+G7jyhSAmInwv3eBN1SbuKE2BQEodGZtS3ery/OC6EYO8qDeRoBZah5Of+MdO7VtGI/o2bYFCgO+acXZUOnb0ZbJR1sw6ovSDPIzUwO/OzcAKknHkj06lCywwJe9KS9Agc7kEF/x5kXceTQk1I0AiQTTBTW/xsZQoT/l2MOWhafHbRM4ujCZg+HYDfcCdH0I9wcRaM+e5LLkSnrQS4iV4Hty+3iZ4SakqPPR"},
        {t="b64", d="erxjR/IaYDV8uOEs5w7bhqwK3Or/QUF8ZmZKgmrA6+IDY1UsU13OM2z7HcknjkN6MbK2pgS2ZOJ9HvYO7gPDySW7oyBRavnbk3UXeMuoqKQybUuuHOhkHLJCPKFPkHFVpDQz2dIrEe2D62MVExhPJqfOe9GVnU090yKien8uWs1xOwyJeiYBCi9h1hxeHlhYb9BBIPjsqzXkqhnrHAGmWJgtSDGOMoPkwF64DJsDNSoU1XVC03ZXX//v2CdpiHHKBo2vowsi7ItP1a+2N4SnVrypLVWEqH/zCk5ZMmMet68o2oFuOaged15mIDmDwyO2XZV3vKj2SDQcn+eBxGH6gihBCCECt7rw/MJqMeFrrQEkaz+gUcfJzao52+GsuK4/BrgzziKLYYglxfrugGIKFipFtb36sdB7BsUnVhEnbeRlJ9p8KhW9aXaOIiynD0lJa2maN249oDTXgvUsqFKSISuLvMCflww/nLK0xrikvbXzayuZUsbjUPWWsor6/nVw"},
        {t="junk", d="37d01e"},
        {t="b64", d="WqaaZVKM9kt23GrZR24FHBz0QlTz+Hr7mW8AUV7YNX/Nns47/2/2tC4VoDvFZwidi3MozFM9HR9BIbrUyrk2abNTU4FkS055Ae+94N5Mw2Pv2IUHjict14DZ2go37MnIxn7ud69nQrEXQxVifTnEkIHaqTmeK7luOyBkD0YEFnZ0qnNarG+5ScII6l31G/rEV/QZYADDeBM0gikSAfqrCEmXdrwn6WuLyz0k45XtEc9Nio+xhfKrqIDb9GNLfbCC03vsyJ2v5Xnep/6sk3KlwGLqikAXrz+1AhFZBCa90LYBSj7PNWfsU8B6rM0iQMocVfPm2y42SLGJbjk+Nf+jF7hBYr2IYRp1lTL8TZSMXM3ZCWvRQKvXC2t3CA+m8EmnNDZ46ATxP1bP2uqOW58YJR68mYcrZJw6eXmKJL6RnVRWIg0JxnskzenfUI/hfjMO1n7UXAn2IBAsHqGc/kBA7F2hrNkkO9ZqlZjrsAi1rjOyKCIjQJjDjYXwXTHYQWXh"},
        {t="b64", d="HrJK+L1DnTwPVsJ12JYniIbL2Sl68FFPBM8up+s1Y5W8BZIayxgLF2OwvVP42XXJN7Pwkj7pZoiJF8J4pnnXtIntxbgsxqaTiPtOJjJK6a7KAZUqXW9BhaGl7O7nYeal3CTF4e3hWKPu3EwXoJVcAjgYOwqDH0hNdJETmFV41Kajg1E1afd4ZTNXbctWEAzYUDEhYtOkqo7h33Co0c/cyC6sZslBSHo6yIeM21kjhPp2fFBsh8/ocQorRlSoqg03RHMO8l3VqzzR13HqBtgsB/l6tTuqvaoI0lZccjc5XEh8oIkCT9dRNLBKuTXODSqt0mX67YkcMu5JomScccKlT02J7Qy21fOCu3b2LPsifoU6i/2Ni5Gx/k1hnhcGf6KagM5swdPsdxI9OsHxWPp4VYXeVZCG221lSkwymb2DhLlysObc7qO0dQ7jj+QSKmKBmrqN7sm6YvxPnbEKLnXVgkB/74cIWJZ5uHvlu3mxL3Vkxk4iDkOzsYxHe3DgCAGg"},
        {t="b64", d="wBKaoU3h8xJwpSpsLYiuIHJrBI+cdtyC+no2pQbdodrHbs1SsXBpikTDIK14oOeWHhQ/5/Cg4WdJ+GMSt5tBFInOodKCd6WoC3SvFIZBxcon260IrlWVnxibUvq3vc6bnI8w8eJLinB2OBE3SZ3FfMoh9RfEbGvfgib6hzyqIrg53hNZikUU6Y7s4zyenj3wm/9yhXlee8GRHBCdgLfiyGIWy6f/RAuw+X7GmDO+N8z1bSxG0RaE23Ex+NXH8LuE6+fE2bm/NV4nShLRpMweHOe1E4rX6KLkxojrzged4BVBLdgOxJ/ZsMEC38gdU0INV7L33D4w+5yuE18TXslCT3M1I0xHc6D8ZIifO/njSlkU8N+ROm18w5HtpixzGoTjk5LtKl9w4wQlLPztiGg7YW6jTjQXtRWLEZxRTNDpR+T/nErOUB6gzc4I3Sd2xYax4G4SvhrIUDNatCTrc50AA0B4tEoCdsB2wFVmGBDkuBsrEfQxzhEJmqglzUAEUsAj"},
        {t="b64", d="sdJYN9KpxzQ1uQavjkpJ+ih91KnMMq+SHWMgb6o3NLbHXh3VOvNWZrZH0tQlcsZThrIhTkxR95JOvvmQ3Xtyjm8INUs0R4V2fVaOwX9mmRnEbGXzRaKaXsWto3ob+Ll209+ygt+commHwohoNTTx1/RXs/rZMvkj2Ht2vgLAq/nOvWcTlhYPNNB9BNnSYhYBhOfP2XM7Uf251KgCEZCrukLTEkYURfxesQCkatvrT3qFD0db/9FSn6lUiHANmxCVbgJDhem0Ye/7k8BlxfMZkoO6UeNnW/UWBNNqpPnsb9PnxC4o6q13i3dY7Ctt/v9rzIckt3UXZBsz10gXoBLxzFNRhd9g9UpMRjS6nNK0Y1ZJP7TjnFeNly832uR9Dc5Znw6+tyYohdlQOifNDe47XitZ0o/UNr8HaZZqG8r1Wsc0GDP1ewBKxCsSlrARie2uw+gzspHt0hQ6uh9xX8pB16qrg3jI2FKcHUx/1k2vDNsiGo9aPCdMCXJeoktmKMIO"},
        {t="b64", d="ZepBah+n5kQbsJ+I/4rSoBZXD3gMEnOxxTWgR+wMyETs5Z9Jg+VF6qgk1EIL9m64KctEtRXJt7+SV4Toct4CguML9g9aH4NdPupdupnQJ+z3QP+G5v7A1GD7PO/zj8FOUn25+a3lpUFeBJwTcXFzEi6187jhJPzQ+YF3skOu15wlp5P61rS2YIqkGcdhaVxEgBPxI9lnwQ0Kyg9I/Bx4CVfFZvuvdlEVJwjUTnuuMI1qU+GVsVsXVByNil3Co1Prw0rj1CYGThd0z/8Tq8ocu0R0dHsQRUUHBPqgAnphlgbPz8d15Hw+OXVoDCB1VldulYw6SmMqUCiPITlZGdnKlJ3gwLvdFJA9pGA/VtpjNnvjbgRvCXsNu0AgtBSSAv++DNxOLwbHdoL0LjdlyWJR5vxMU8U7RFM9ezcMd8Gxyq8YctXofsYMs5QziMMNPvSWFkcjpSR3r48zZUGO3QSx5Vf1bbQApk1azPDp+jKVUoVoGhEFc0fDSDtCzr9pufv0"},
        {t="b64", d="g5X4OpMUDbTTsnctQnNpU70inYj+eu5EPv65MWYDkmKHgDmYfbgoMLNQ3LOJW+BJqAOUTeEezEP347nPUV65mLb/3C7IeYGg0QYoqfWRRvq2c1mEsowBOp63xPQDKJbnTFN0lSwojTSf11uFa+uiwp8OjbqHFci32hpshnqEwqlzF1Zul+COpfy3MsJlS6jE+dIUf01uqrvEdWGPmNOySuakGRTZHIHvRE0CKa75dUObNh3B9XJOMZmvhUpWCDTm6cNiBiiI5ZfE77+W3W0lDaYS84gbe/Z1jG82CDp69lxQlC46w8aPwGB464e+uGVfyCh561VjsVYZwXrjSvDhWQU9c40Z5PKT4uO925zwk+db0/sm/J8KlqJHklyt37cQgx8+Vn4mQWD+YwqgJLGINNADfxLPQW4KLlA7D+vsjXBrSy4uzLHA+igJ2/yEjBbIkGTBw0BpqQymzNRWomAIwLTnukZlJp6t3nI/r1vWkmmxomLZKzGcKKq4auBIhY6+"},
        {t="b64", d="RLnHek77/Q0e3d9SC5077HVrI5eZDtLfLsT0YUFcm5hySeuiwqL1E9efMdb3Cogjukt9TpRoPCF5RX5fcAcI8Hr0N0Er2btbxbaJBmQixoAcxjAQ/h9/LwxA02S2PLOPlw0A4rZLsMMRlt6sOyo43EIVq7ljQQphhcl183kR4n5Gbd1DbBrUA6sSpIPT5UnsrHe63E4hzUThWR42uxIFutgEGVIg4yhKwet0Zc1jtz+Wi9jdk14wwDd9MXfV0O4+KsA6oRJYl2b+Ee6JKu5tIqU7gNyjp8Clwp53WNDVyEAFqyJ7mDGprddR8Ed9QLv+UJrdyE57WwfJsJFzCCNPn1JB04ISqVtcgmsVBLFNdUogwSiNOPYyzFduipPYYwslZJtQ6JmOHu7PedGC6R77dyoxOybT3hfi/coITVCQBd30ZoukJDINoxhJzvaFjTTgopTnYXMZC4RzDrqHhxZws1GST6ItCX5hhUVgtR98pq65ylw79micynjM2eJN3lIi"},
        {t="junk", d="5f"},
        {t="b64", d="cuj954lUDe4Cg3myEpxgnWfSop1gTq/VnZ8gK521PSz7tnN2I9QTMoBfdlOxzS34TmKgfIHR5+DBHqkAZRObtaMDDqfLrOPuPXbm57LDUC0I1kTBu50jCwctS2oDH9W15lssu5zYNtQ+w/SZEyhry2LQg2FhfDMEnOsUa7hwB9i+hUebjvWiwV6E9IIA7qk3N+j2q4+FRwPr/D3nG7fG0S2Id+FKj3/JdbVp/qIBxTgm5suPSozy6Nm3M5ugjApb39TLX0utknFBStViGDl3g4m5O6+pk6KjBvzpwi+kPqvRcwnIAJujqkEFcp3kPC5J6fPWF56mf0ULqSk1GG+B7fUhDl2mKK6OV0WUWxrE+svGtJGzFtWLgcEpb8Ndxx8IL93OnYTKfGnSFTkqkAmSQiY3vw8Xl4pCtOYmcmBPp8HKQjHasnnGdWSPnMmb/FKAXnFW6MvGOj6XmMa2nb1CkOjQo9nW0G8TuF21SJ2vIbJdsjsjAONSapvzDg/QEaR9"},
        {t="b64", d="ndwPP8g/+CfmWbLckcSYB0VhcRurU64HPFl9imDzgRcREHOQ5xBv0NO3+7gENUMwzo3EMCQy/Z3YWNvDIfMjbnveq9tBhT5RA8GnvgfkfCbkt668dayGNXL+ZqRPlLkUXjRu73mPWwoia4D3oGg/KpgbRpIFkTL57eb/qP++Jb6mJKLgz+YXk7Wkz3+BzQPci0ZH1Pn0EN4wwRNG4jsKSVhGuDXXhXCAlxdOtpjAsIcL3RFWlO8A/fY+N+87veJGB/grw2spLHS/Oqextct52k8+nH3As3UyXoZmoiFQBwDPtCF6i00BfmX7E+lahn/2vwi4ckiIzTZjDWDQXI+Jljojmr+NyJRNQKMEDORgumB35LJc/ApPqoUFIXtEsLQFwgAkWsfMA0+csncCZLN4YhQJ9zCYSMWkTPIY+GR69yEiOnKPlgRxkSW8Xs/7adA9F/LSj/jGWQ2P899mbQnL99845wtq56T3+fOlT8EUpdmoBa2Ik9S7xTnZK0H416MU"},
        {t="b64", d="gGVc8Gxgvl1FT20NAzqAWDvDmwMEv8++LiF7rBTBq4Bg31og1QSNlt/kDQHBOA9TvkfoQ7XV+ll8A+zzSLJAVKpl2ZAWGjA+EJFOMYFsWBoXKaoa8B9wa74gItF8uI5CsiQtUgQQ2kf+397H/q8qzdd4M6C4cCBe1xkT6LeXp/HWzI+S4bIA/8zgz10sMuJtu8h9VSobud5SWlZhTqi3qukpliylSJDLIxDVnpVDkeSVmPAMMVWO17yUUy63DMh18em35gtXPX0AifSOgN92pJ2BlnmhN7M4oz0HktKKpIVLy2PLluTmuzZKGCaDTER6d7XHcCC0Cf0tE/iOueZJCAtFGS6wgTeaQZu5mIOg26uzv63R4gcT0n0ujmFM089y9LpAY4AaDaRtfbvkAsEXqTvTCApEYFDxhPWawPgYFUnH0Icgw0zM45SkXtI9DTBpk5HKtog6DfXF76Ygp2rGOs7tQmybo8J/cQMTnlTKoHdifu3rRDRa+1wgAosNadid"},
        {t="junk", d="cb"},
        {t="b64", d="Dg0rOOEruOola+A8/PyddraAE+MZ9d8na2nk5twYyd/kcVa9jMEtDXgQ7VjtIjdzLEmtdiAjbAc/mlQc0DBSDnzyJup7g/J/Nv+oz02sxCYM14DT5dESO9QmMAExQE1gz53veQWJciKsw7KKkLT+2A7V3Eq28mP0ImbYNZCMZeb6xLQmL9019Z8O8hB6FcH0vA+yWga8P7+1aUYy+efrgHbZ/ofpXk8IrTeUMEcw55Amesx7PegSv1Lni9udrWBKMBkNxbNqz5IKtSmldIXq5fDX0YEg0B5hWfBUoGI+dCl1ZdhYI92TuJF1BYYny7ABt5qEfPzwnkMQ05dsq+D3Fbe9eKZeTv0TR8N9Sq0apbj8RiSL1tgIrFbaWIl6YXRY5frjxn8hYLSUlWygJrUHxJljm9GYxb+ZiSVfcJYXhUr19YIs8ZXZNNRBYRjIXWe11Hs+EPapU/Ihw5HorYM3RkKJQvXgUVXg7EUJNDmVox1a6bt14krsGnC1djOCOZM/"},
        {t="b64", d="lFKW4LeIWMyrZrcl+E7/U/b49gPyGfvvtGrSp1zg6/ZTg6anpu//axyd8cIlmFVSnb8YEvqwPzicpFkEYKjc6Qr98rFy1e70PI2/66q21SADaZJdN4ErRYHOk9aRH10OHmWU1cy31ph9QvNQ7pkkZZyHkvB+ALo/YPnOls/9z+iYNqsiIiZrZUtDG3j+LGAF4i47mQP24+vv9AZ6cgcGQgXosI2LG8ZwxNfGGR9k3TTU7Gc4B5pNc6MDU5MxbWpqcaE3zv6yWIsKUTBWZYX6JjiyS1TjLJz1qD4WKFRtKiNjahsVOSuMhjn2S/FN9vBXVrdlgns+BYKl4COypGd9XvPFhYoAtU4xpbvvASQPjySwK7iwbMaG+8psZq5DspEfSornwjhsdWQBUCGkjccfwu1j2+TB9B4MVbNdU6W6G3tP/L7xcKUPyrprZ0xBo3O70OaQ7m0vPUIX0HjkOknhObSnsbMKbjugxEZovouwYR3mQqICj5+V3iqZ+d+h1+by"},
        {t="b64", d="5BpyWF6heE4nTzIzHetlsPvDpl2yEaB0Kf+iLUowC57zQS6ABh6/M+LkhdNltQyUr5Li26z9aWzw395ZpGJjSA2OLNnocYVByYEKsiZxuNCuCD2xYF4+H/+YHgyzFPkjy21ByyssFSpP97TqTHCCrk1CuZ8EhklK1pYNsOrZ1yAQvYl7sBGC6mMMU+R8vwsj3CX4d9kNUoMGh0teU31o3lDhoBaEp7v7QwYWjRjWKt9upquP6wRlQWNgkQqGiDjj42mfYKEkrG4U62BV+BZJUSLYFm3yEAsbcS1rbnbyi3ATG62D8uw2YJqHEbVZFB3s7RKahUaXvTs9W3yXnwioTqPYUt86NCfKM0OWzdsSQQnO6/v3qkv9DeO9LoB6fqgDmPykcno/BYFOIsPSY4fBoaiDEtNQOLK7Hl34Q1E8lzyWOCo4ThYYmvf2zaVinKfGdz81Q9P5ZFKL7eUQoDUtBQ0S66b2bi7S9MJE49JAKwxokCOuQAhlqzesD/igjfzV"},
        {t="b64", d="tLxna4+KJPbeX1XLXl1poG+NGtG5bwjqukLSecUdOTzwrjcTPCzDs18UzzhgOCZ2TaPV88QHnM1zcdTbqMzxG7VQbGJntho8TP1O5o/WPk+unEu/untYgga0/89BuJC/h85ZgeILWnqXQV2+KwiBR74ScDxpbhMF/ZH9DjsFh4T98oBBgp5WAVk7L2LTsxa3+WAG5ZFJkjCX0z8mQpIwb5QFlT1GPognHsASm3LdZvA2eM1fykXp+efDc2/xs/+nkYA47C8yYql9HQfVDoHvRFaSBXBtSQEOUFI3CF/sysysTnqYLIzRw/8/gvnqIgn9S3t9P6nA7EHty2h7yxjvPg/+r0HLXyDwJNRm9s1MqO00rTDOfvSO4r5qwNhILj3JUHVOXcVM16ksy+OiaTbZ1fkKWh5nPbNfgaBFIoRhDVFnD62s2h0JL/WYRck2FwTJWRRGFf9mh61Es3eI35xq47edHsRj3XvlmPs5+787I97A2OFUEFPa+IqZo+qZhwXa"},
        {t="b64", d="92P+/XNSqO835YLOsJETAYy4qt24Qr4xsy9exMEeFTO9MOdHw1eikGstUxrlkfe/iCBNY61mfynq3rquE4zJvuAseEJ4c6Tzkaoz2eP2LOcCrze7Hm1CdgD+qTGnbYhKQL0VGOpVOEa6o+wL+B/MdxcXJ+wANlcQYf/Ew27/D1UvTjopIu12vHDulFFpXaBxJQmnU+xijVau9EdJeUstlJoLpN9sySHSg1vYtMobPDFVYpbyyONfp3tKcKwOfJD5GDMfOX4WVy55RQqOELIkgQQFahEhYPfZthpNGAFK/L//BnKGjInABMuAEoGeA7J05MEsLjO0330RHnhrMB4DCM0gejCaw09zjUsiLXGcUOUIoK6EN+1zKnrOTCMF5Kiiy3fZFcIZCwtj6TFjabl908ArYG/XAQyNT2BqFIoLQADhKq6CIo54axljfo4ih7ad4R+EabILK6iigzoA5iQD0bJisEc4S3y3AaLdm9RRRnqhEEng0zsALRtHXqj1CvbL"},
        {t="junk", d="1b2d"},
        {t="b64", d="b6VG7eZsxXs+rCUEOu/g2GjicZ+1q0UQLcDqOn7xnmrJzy825YmjHKm3Kq+fTX3kE1g9kEcmUmzxsYsPWAcVzoT3qDUQ9v1JTOXjPgaiks1N6A7j1FIzyGu/IAHT7TojC2vKRKsIV3RirZdYRC09tpSxD/ywF6faAm6shoyfQLrnZZ+lRacERqmxg7BI3DPCGLFWXundWRqCXftQnzSfnGgu3BV+eGXAA6qFwtcMbenm5roC5Yl++G05YlLxnElM2eq4V5SQlzVp+MyNp5x6E38VqTY5jYTcTmztzsvWueeh/x/5T+Q+AfMWoqTUaxIIzdRlD0pKqJy0LJKE9pXgBFpq3fKKAuNC+E4ZiiAOWDuCV/QuBAocLGnmgCcVy6XkaFkuKF9CtvwtPiNUWFlIow33SPH7WkUiPiGlUaVU1SiXV8TANMJhV1asX0VGJTs9XjFZ+0nXBAOpoMGEeTstOxyP3WuPtzO14tTYyD7weThvUZwrW+q4QeCuRdfHFp17"},
        {t="junk", d="a3"},
        {t="b64", d="/NIYBssRHEGUrWv+qIzR5loRVSHUmrRdk8wBD0yFptW2EqcZ5QZkwX2uG2HmgyQnOzC6N9DdYjIeJTKUqjpwmeF3JV+LdLwQ+PghEDbrm5SBGQvF3h9gdVbr3137O7wlkwyhUttteUhDGdmD6MOA6O5NEVPRkzSTNjOhD9ivELxrKwTXGqR236bZBUrlbyKdA69zu8hUhpU5jFFBYBTf76SUmv/OJ+2L/9Ycfr4aovzUvonlRUUm3CJtukWu39jNTHRCaPKOdd3SbBosdxs5cdR43XAKqDA8BWx/F1hoHPtWml+0STbqO4TJYg9ivpOiyp0LcWVroLJ2h/t8x9MpLaHbmtgP49DSIx6pe3TPSBpHCVAQDHs/g6y3nVeWMCt+QMpRYD9lfgQWoyxSS7Mkrr/3A7O2teVACfz0OEGo9/y86SttEVYhpT6r4pwKkTMWdhZHF8iy6ISMP0JBrONri7fTOHYCpE+Eguu3Q7gr7j0BqbUdjI/Nnfcpmm/wICtn"},
        {t="b64", d="WaTe8Jepq2kYvC6wXT/VcnE7iDpFZlXM0ims+nXh1E3NScAAagHdf2bQ2oeePPqTNoQUyFx/Lpx5tocrWoKVIKdII4nvdU7/xEx6TA0N0w677e7wwcuM1Ig/p1sgMhqXFbjTCdIwxU3bEbAua+RRSD5XT6KP1nf17ymJSCJG9bglGQhg4YdlazM7eDfv6eg8S6td70tAbOLSc1Uqy41N6zy0nWM39YVu+qKndmK+JFjBFwInHQ/BdGK60niqOGaPUYv1Z5v2bTzhMfNSQQWkJr9dKAD8jo2AZkBS6IHXLRt6uuhFKFdwFl1aAKpm5FX2oiZiDx1UlluvUwUIaVj7mlQLHmNXleBwjevjCnYYl2WkSaG48MBECVtSHSLMJ93j/PkDBHKISYjjazI7z5F8ewzpfuB9saGEdAYmtl8cLQWSnHmhDdDPtpPwr2jUJw+GxRQGesxYOUimG2x0VS9cx0e1FdpRvrJwZFppvXl4pnJOMvrh6n11OvmDZQeCw+28"},
        {t="b64", d="wFi1iCLGxGTDdvDouU0Ttd5WejdYy5rFf4jnHAsGgRYUJgq/yXp5Np91yOY5WJl8z4XRyTUTWoYJXuxkLD6u51ZYyiSqM58fgaVaW6THxTR3a73Fca8K7yGX7ZNSUa57D9YnIiufgsQQ1fGfXtMHetTi6WCSclxXAq3Zub+SlZrX3mxGKr4bG+TWDiiZVbsHOS6NdwVhLwWFR2PaT8pZLCXhLmKUdqDaZYg8zZZiQDaT6ExELzzaJ3WJ0Pvx64kkwVKlBjSl0gFvFBluMD1iZTXnJQKZwUccaVAejvR5S+PINh8wtGlkDDCW1oY6te848z6ULw5muIx9WD0GlkqGgCtoDhmXHlfjJROVnXDKKMdCSIA8voqPe8gAPz/8uzk6LaT1IAITw/2d+LOHpEUfc/J8htWRloN7wttNLbDQrINt7NgUxyPlkTVnZkT9KCkovAWNLU5k6l9fIjCKimE/p9hpF+tV73Gm6hbyvkjGLquQow/jkb2CA5Mw2NaSorj6"},
        {t="b64", d="Ofx4jiUUoMarsR1yO/XJHRe0hNwA1R5SOLw+N60gjDReMM0AUU0wFhmxhXG735UL2Hi1G9D2lWvCHDRloSaMCYmKU9/Esod9At/P4ilrWnnxl99iaWB3xoFpUGNP6SQBCwhoiZRm0dOQMiCmn/vq3MbcNMStus2rgoJIrRrzEaLI4sNAmME0iyU1+FsS2dK8K4arhtAuIV8/Y2TxYANog69ECtUzQFO2p9JjRuH1RmtGr9qIQ5znV3Z8wNUsft+pJ+MBQ0sOSV0CcgeDqX+vANkVV3ZYMHvtYibf4rMI37Ye21ZDCjTotJr8J46ssNHq4fEAKxzt1mtNs5VTNRgIFJqztW8G4pyqNPRplKsb55FFPNWVgGjGXEU9N97DA/CMAr8xKgjTl6tt4b0uyPcaQiOd0u5uMcyXYBQKp+B6YP4V901LdjXqXbWkLghb3i/zVcvemzOfJt6TCXtNwdYm1oBnwq74lZ5VI0THHq4W89UCEYBs+OZOsTJVNJoN0SEm"},
        {t="b64", d="x/h93oeecZfGtb5PVAemLQv5MI8Zo0ektw3x2oJs01Id6tsJPqcsBUG3NNzv/v1BCAGqPksbQksUt77j/C4Y7ODW2sZNgQqG/IpQdi+UJh9QiDd35tmVRd7lNxeg0l9S3EI7RnLiMafbAsap0ZwedrGCTaTjATctvAiJTSdwSaq44/W3BPpKF54bhSY1/aFIg8c2nlipY5ySjhQS7yByuC1B2yLPozrpzItxENBP3I0Yp721u8+Lazzxb+kCwsB2EaJfqkb/PtTkeY/iQ5xZDuzw6AehBOijwQ5kfjV2CtcBqi5SXBbFpAbQ/+KaA/96K6WFKx3+kRu5at++dyVHkGQ31mL+XkY9AlPsTs9JGb9kKcCsQKaarxmwC/2qad/mlXpoY+e0iYRnyKFADvQUwi8CL/Ns7l+jK8dgOAwR30nIf6BMQacVZlQDnVXmNrp7g1xVr3ZjTppYCH3EpgIwPohMXQsXhnUbKVSUpv5Rj9CJrpZdUqfW5atv0avq4vUM"},
        {t="b64", d="BVvMK06UKv3yGAq0HvtLe1rDdSnHsQhbiyPyIRMDFsfSrxWzJS+AG81m8kHoWAJmeRimgtp3M0UEJrnBql0a3WR8qa7mLgrauhlgJ9xhwpU7NBDaK1Vofzo9e+F4A7q6uBHdTXqvA2/2Lq6rgxBb6Mgm1h+FgyHOje5yDbW04qh13WCMco3JJO1fQzfdONNTAtGo65n1k2w4UfCfgO+Tzb+adhuoEhj/Fm/i5/xJCoHFolhARh0B0aqvHdt+ajDBrmZXAKnc28OJ/5v27jHwLxJ3gkkcsynANDPIkD+brwT02/FS4gkPtweLv9yotYW4sh3nfDoizPoJmgwnnTLA4yoIvsO3LGEinx9reEk8eZmtl2pCBpb01S4RFspJn19/ycrbu2WXs4T2XZoxAmWPhRcAfcmPoKOIvAuJcY7f1djRAirs0hRQwYE9CLbOfqaBNWEcVGXpTP03LIopxJiseCIZcwep3y15y3MzNWF6RlRx1mvApqXxUMVRvafcrsjk"},
        {t="b64", d="rrtq2i1rG1FKP5yQvjEgKVTxOj0Yl95kdMnQ8KbnUfDWsvliFP6xmCNQHgEY2YBFOFlUV72e92IXoCU4k3gJkpAa4gYlWhR/Gnw0/SahHOH4lCcsCbkL51K0PB2d0sBmAus0dpuvnos2Iqj4cmu5dIQR+5rh7Ln67gFwu/bZm8uETQe4YRRIujMBepq090ob6A7QpA2RpUhxlC8f4/yTWkITQKBQiXbftAzfPe52uLDGybabnyGZn2y4KkTZG/PWtt35/BYMlgoWIIwVEGcre8rXYUQv7ePpUDyRlbgKAz9z/pCzk8scZ0TRj4d2ecTC4Zln4nMUbklLlva9Vf78L78xfWhrloTriv2eyalBrvC8nxiAa0Xd/+JnQsJTtOjK5A2wCgnj2vyVkUJyQQYihB8xD/5Sd5R1bC/Jrp1ueJSJxLfx0kBxXVJfkx2TjlSU/mJio12PxGODjFSu+SFYHdgus/xg5lfK82grZ22ftpGJep4GKswqy1Th1TZCx19v"},
        {t="b64", d="CjmnJGW08LeSfaDSuQSgd+b04xrKflIvABKO750sA5jH9n7kN400Q/vr6jAhoGRJsPCKKfKbSpfVJ0qqxaH1PUg/uLz8QbxJpY8LoxNLx1YUNpA8b2TE9n2obfWCL77wSF1cCdIE9314W9su5G8qI1bBvI+gk4Pva8HQxJto4JVvrvikcQ7jU5scifzLdWwk8u3h7InQtC+jcfTGO9Y/HKYVadh5q0mtLynwoPxs9Bn9gKVQ+H85eXZ6JfBWsu16yXeSD0psaPnKXBRPSDjpWlYmvm7CSI3tsAIzPs4KoLfvP5JegRvnD5f5ZtE6WhKQH06SqZyGnQM/wJScnXVqfhVcCTmLEVEglLj/YyoDulzZVf1/0oq5yaxeaRZOCgR0xpQFMin53nAG3Kdd/NoMkNilKVQoPdPNXGoMykHZVnclQgAu6GGWRhMTWVAveknY//MmW9PAMx1j6if+zBJuI6+e1nvNnylq7HX90Nj9JBocXnpg8y4jQjxl3We3yvf9"},
        {t="junk", d="ab7af07b"},
        {t="b64", d="HAvZ+20BVcwV7m2cNw22qP/yvTFDUiLpM6yEfcY3SfAbnSIMbAKWBconzg7Ukp7Qa5ushDc7g+cxE/wZFaVW4y11ohLN1PkZZOvhUK4RpR+9g9eoJ9gFXNi/LC6gJm8mytJvT54cuwkGwFZ6qUcM/0NQxybzFDEvNWY65KlRnUFgkQ7EWWIvdfaPo7Kx19STRr0mkke+8CEx0bwUXpDE0HC+fDF4rADnHzUXaIc8qYL/n5fN480mauKSzpW+WTx3xvJUHT/qT07LB0E60iHaBz+D8U6bOuxGmyeGCLzCi7DzxKnif+MNGhEGKlZ+NLC77E+1wUFLXcfM15xm++wYGplU+sy4XSYmy3kA3FdVXobtrlZ5ETDtI8qe7MzIJhqPiqwPad8sKUAOZnzyFcKyUNcvq6bx7NGMDKqeAPi0jcX4Nl0eIbxqFO4Enw4bSNxxdPeg3mTjmgrAqJrMoqcERdgPjwChDmKCMyEGW6Pfn1d1j2M9yGNu7oJe4Kl2Y42H"}
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

-- 🔒 Sanity checks
assert(#AES_KEY_HEX == 64, "Bad key length: "..#AES_KEY_HEX)
assert(#IV_HEX == 32, "Bad IV length: "..#IV_HEX)
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

-- …Sbox, InvSbox, Rcon, xtime, gmul, rotword, subword definitions follow…

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
    -- 🔒 Sanity checks
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
    -- 🔒 Sanity checks
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
