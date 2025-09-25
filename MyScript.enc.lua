-- Self-decrypting script (XXTEA)
-- Disguised XXTEA key fragments
local key_fragments = {
        {t="hexchars", d={"9","2","a","b","d","c"}},
        {t="hexchars", d={"7","4","9","c"}},
        {t="bytes", d={53,25,86,239}},
        {t="hex", d="6ea9"},
        {t="bytes", d={146}},
        {t="hex", d="59"},
        {t="bytes", d={51,109,93}}
}

local function byte_to_hex(n) return string.format("%02x", bit32.band(n or 0, 0xFF)) end
local function b64decode(data)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = data:gsub('[^'..b..'=]', '')
    local t, m, a = {}, 0, 0
    for i = 1, #data do
        local c = data:sub(i,i)
        if c ~= '=' then
            local idx = b:find(c, 1, true); if not idx then break end
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
local function rebuild_key_hex()
    local acc = {}
    for i = 1, #key_fragments do
        local f = key_fragments[i]
        if f.t == "hex" then
            acc[#acc+1] = f.d
        elseif f.t == "hexchars" then
            acc[#acc+1] = table.concat(f.d)
        elseif f.t == "bytes" then
            local tmp = {}; for j = 1, #f.d do tmp[#tmp+1] = byte_to_hex(f.d[j]) end
            acc[#acc+1] = table.concat(tmp)
        elseif f.t == "b64" then
            -- not used for key in this pipeline
        else
            acc[#acc+1] = tostring(f.d)
        end
    end
    local hex = table.concat(acc)
    assert(#hex == 32, "XXTEA key must be 32 hex chars, got "..#hex)
    return hex
end
local XXTEA_KEY_HEX = rebuild_key_hex()

-- Cipher fragment (single base64 long string to preserve padding)
local cipher_fragments = {
        {t="b64", d=[[EcsQpmj5AY1Iw2mEDkuW5qLfwuU41+iaUwcvYe/dhoins+zQaMJgOtfCO+2lTRKf2EW5dbIQxjn7or8wmCT6MQCO1UrA6aBkySXs3eRLIs2mREQXPaQ2E3PUugc1i6zqmCHz4yTdDPbveSkQMYv9B9xjsj6SWx8gpFoQK10INEGSxWED7v63VtzguXVxfUjESccmlR/svj/brFR2FR4XboPg84a8r1pO3v2//Q5o9hF9IYZnfmISNhth7YxWHzeAfeyrLlM9S4eHR5ipMhbvEw8qfg4hmg4FamjSwrCbLS4fW2U7MYYUtG4eLdLQhRe9uDpmxlPFKreDBFkgFSYE+qU8TMp6B2AHZqoz0D5D2I9bmJBXJVOEzldR5FycmmAyBeAbTTPHBIet4Fwdyd6kuC83i+D4qNuHGndwpLM616+lW9Ej2GvxSJQpwrFXTfbxLUAACyNXZyffzOtHDxFzGY85VXxSD+xfiqE7UH1iB3TvX9g+1hlB6Lejh2UKOKjujr/0q7RAhsflIwzKSiir0t3I115YnUFbrEQd12UQTVXor/od/BsNbEwWO5ZJ+GcN34TayqhRujunUVNPC6HQTfA9EDLmJfpnnIElxKj2nAiaBbRxEMaNgPQUagVSD6A0CIzHNgvWYNbfgj0IilSNmPIYlauy6GwaR4PcGoMKUTOyrxS8u3H6W9/a39I+l7J8MY08d5fxEfk1wvgYfhmikJo/neTVlKf95DxekXK5R9LHnZGQvZsxCtI+9ZsxYFO9cL8MmPfRxZhejpO6m135xZsGWMKotBqDcB/wUPFdI9km7MPnO+ztjooPWHy27s+Hfg3S8WvcsZYJRvPDYkxSN30BAHVx48l/RsqbidHAvXYhjTdQox/4EBeGGrDidT4kRl6r+4PTd6IphEa6ZYAeQC/QunGQcPvzdKAObPhUvIbm4cDtYAzyLIEzfgXaSqu6Ww/occvYd08uxeCW8Ta6/gIx16/dCDZf7dW2dUSGtTJG04m1lfx4GXukoYYbyf3oOW+86UswhjONv872azNAsngTvk8ptVr+0SK+WcUsFGNOo9XowxCJWJiCyLhbTWOS0Ld3Etgrny52Za5Bv/hwu/hH7FPOKC6UWe/Lhlk2bt3Nvtg1Xg5whckvLffyHMsKR6WH6ASoqxJAkosLI0+jmfYFlPeAGtiVriuC7yXijbFChgoA8wnQoinGB3JrlTaCIx1JXtTZmGqWiTglhk9NGdlyzYXezsGvXC1+0nAUiO+bJKgnluYMV6Rot77lVVUmLjRfhe+e7eRBbXMsTPXv67jnb9BHb/o3F5joCLNN/pkJGXe+1wv8e2coh0o4Yh/ZsTDew0EjCXynKrDpsETgbsby3J4TKWAOajz34oMlZhA2MU97Ui4bosYKNKLJjRyQwvzFhhJJao17d/X3EHqvfpxEg1GCokknMQTHdN2uNY30Ai8oqjM0g+vn3fJ9RYBtExMgO2SExZC73QsIXxfjBZEVDr7tCpvSv8BNOx1DOQb4SVFSLdyP/Z/s0AvDBRBZIwE4QT6ci0W0vQn9ZEXBR5nQgczDuj0DN9ZOGkm8qd1PmzJVeFfhmqjjNfTJnfQEOymgp566swfP8aaXd+U0++HUYXQBi1B7amR+vgMfJgCbW9W2NJLS94BRYdIc5uIR95O8gbq7OghTT040siw882V+E2qWMBg8+Wr7v6JbX9yP5P2M8HUaKdrdl5K6Rf4AyuDccvrl6jODrxNYW//+7eEsXXy2KhLT7VuZkiaTUKngptsctvcJd+0rgqIcdV+mZy6wEMpWr/pWEroRA/sWXYR9B7JJCV+vzZsZag5mjhrYmK5fu49IAmntB5RDRrvUryhLPGl6XUl0vWudPaY8md6z2As1bhgYSWpYM9sxWwFy7NYiJf7XzPP3jytQcWQKAKQC5ixU68WvzVBebpl4cmhVMMLSEbVN3j96c3f47fvgcCaodURywWCkQZ4pgPNPw/dlx81qeHRmMjBM6cxSBLwQVP2mx9WFzQBAVMaooEXDrQUCntC1csTxEIQJyj3V6qfp3irqGjPAgCESUJ5Gfg0rqkIW0m/rt7JxrsertWJpK3wSt3UStFf40RgKfGhLW7TKcJc/EU8Kw1y+jR8aluQ/DjXUAE/KRjZrGczA3kFUe65pHhp5yQsNjOE+FM7WH851T/Tnc3gqnV4jMA8K7heA3dYlwrJgvFjzvhJhh15L3RtvUvU9AfDGliw+pF6DTtI+2l/oNVLJSrfUmBZYKO0z7GhrSlk43jsOzM+N8nQjee+eM2JA5Iwvi7QdEaN4UnF+z/j66Go/es0qCWFCRtOmFcjSy+XCCPM+CWeePJo/Yas/sOf+Jmk43ZOZrukXZAjVYhFhp9xSFi1ZdEVJVVmkdLV681fx3OdvBjSXv+jrzFwfcUPqY8we+En/lu2MjqhGtkJkeR2f0blQnh4KEkS/wz49EueGhZ3ppCD6Gx9yctTS6kBugy9S2ZeDDdgRInjkCe5R9nE6roXBye9+pwF27dwwiDGqTUv3Ox4TUw4efKH40x4TBDH+dqHb3oz7BRpKWXLai6Zf+L3bKbWvnj4dTIp5actnmPXK66uVxRQPWswYs0Dc14gcpEPnKR5DY7K6ASto9F/ep4STmru53Oazx5OMG3EVSnE/uQH+ZpUP8lanVcNff2fovFUwDtA0lG1ff61VcLylYZxDPgGiqCWggD20vAFqP06uXaRTPMSBtd828ialR0VEbU60zvHgqBqzERDlfEzx+12j9qytubTrZFOKj7gGcRgq/Auu8PI26GQY4/f6FODoXx+DOEPBiMTp0uVwn/uzDCCJuUVkK4y1PkNa0//Q3w0fJZUPker6Ffy2zTVR0Iv3hDNuQHsD0BU65N1LOFrWb6U+Word6Y5q0nPJEjyqSAxcqrXLLZEYkp35mCMXyRSDpKK512hQgVUD+MHVUtHrtq3Z90GlBVbKZdfemN/Lpk2wYZvmMg7dDT+AZgoaXIfmVDTCMOycX6Sy+rxc0No3TObiMAX/4/vtWfrcoVEB4FJ5QvZwqIj8v5+k+NGyx27vBz4VV0Z8ZoH2Fq0YnqUMLpdBL9qfP7f8mZ7Iq1bKI9yNlBG2ffrGLZXN1v9hC0vwzPqH90Q+cDgEU+SrFx81DBJnVjzG727mcntSdcD36t+WNTvEV+LztkAcy/F12B8yCL9ipvHUEvxy4q/FoIYBeukJ58InRa1XAzmQa6+HATXyF6t2M2qFEoi/5gpTDugufsO9jQgqMiKoxgIwVpRYaISjkbahI7yGwcgUHsA5pOCQFmqzUjsP5L1TcycEbQhQPlS8UAunbiY8NU6YWjBTpS7BZKTmallMSdW4unzZ09u3GckktHtpctTAFRg8SoKjVvghsih/iIEO5BjmWj6qRWbkyrszcsYLd/1pwH+vqHIVSIC770xLZNxXZQBAzKEHwi7T2KvQKtRv9lD+iolNzpb+mjJX15EH7jOlzAlt+JUfrOIUNmQ+jPdsW0z9lvSGG4L6GUAuiUUTAPUua6htB67LLx/lIgF5ouDrEWAIIHVK32jOq1y4gyO/A94N6LWVcXhvO3ALG/4gOytq3WXzKHlstsS1zdprpRO/iULeZoghSVYekBiOz9oU4pMS7YFo/q6L94P0I1HaH7EmrifP6wThfvmQ/PKglrHxrchvdkxaaScdVIFp8o1KahLVPlvuc+dr3idSslXcVZnIZPNrTa+PtdFRL6S87Preg8zg63gQ3JNwHn2YSqfL+fAfrjz42/oEgxty865HtnwH8jbWFfiuyePBNnC7W+YjlzCP0aJj0NxcPg92kv4Gi5ZGu/MZ7h5EGmmmkRuGuypidUZZE1l8/Fa9UXTZOd94un7wfCgtNT6/7lu1ZeNvW4iO8+XDOfnrCogIsCApoSULIVZFCDWkpz/xhikoFlx2fg6jdIdDi1ra4tB5fva/WR5+qSoxGtf5PWOglMVcGy8cs+B/XDuw+HpMybd04yNdnXiwI6fpp9b24yy96P9HUXvxHoX/rWbrsl6boAh4qN6AdRwpEhVM8lCIu3mgTdCCnsk5CW3CHNN6kIRNKi4E7Br/aCc0EiJ+UqrgP6e6e6PSlCzjPOB9Mo+0CmJfi43CZHL49IBh01vwg3WNjmgrLjL3NhYyHci/8++HQw7cZr0nfnJOiJZBeUEsd4hBFrTjfml6fuG/0S7STDSFkKMtrQARkwBoIGqnDX0mAvbzW00W5jCr9oS3LGmrsrJZ/76EpO4NDN5VwXFiRQLNbtCEm8rweXI1/WaD8yBTMVkgCrDazJzJMVP/n6XRn6RcOo23zW/99h0vDR4z0QnMAtsO6D0y8+E9ZJipOI31yBBeqDXAQXePKE4Py+l/sWukfIM2BRj0MEGc1fLudBzUTTNUwbMYz6dy+Lib20r9jVGvEj+kEupAyyPVZYQamt1C1XgB6y+dqguwg+MyHWKXpNFWd16LhNwdS08LAyokapB8fhmHrS3Nqn9KP8Qsr3kFOP2JSgXI+wUVxsYBt44LSb2BmYIEzLj/4InVSYCQfv2N59OHlPiGskYAkPM4+DCi73FC47Nrhoyi7KTh4ORNqJLa/S/EMR/UzbqUc9+zFHreNxFcEVfe62XhC17NtpTA/Z5DPWqNMyxvmvtCN9ZCdV39awFepsRCwghuHT0B0DMBeF8cPf67CX/DTwE/hEFzM1DZ5cqrU5jHuF718OFdpcHvSTpvQNn/0VM9wedjWh83XVAqNc6iivY7MgHFbiVrdB/Wj7GAJoz6asc/7cikHCU3Njhfw4CvDxzdoaQtLASJ9lXaD1SW2e6umOKB/hPFnnnaVuZ7gJ9uVCEAhVnu3ftYQqL3D5yQ1i6pQfzwJq8qA9r40AGUTh3o+45sYKpmv+4aVptHingDRzjRc+AcEgR0j9I0h4RqfsI8UuoQjeMTOokQ7nSfiJh1g0SfNAc3nghh2yzsrDg/OAHC04A+hyXXzUwgw70myqanULA/HqtJDVXaQBOhGjbUUxhKk+wWyF95rfvVji7TnlPNK9AMbKdF9Tsm5rr045zcHNKKeHZGgS9O9Y/FrproQBr/KbmrOW9/9z9oLQesKRsNvvcX7X9TVw1LZjOLlKUfpku3JvuhH+98eZ14n5Ay7z2rlTv88kFBDFbaE/sZ8R3Te3PEZlVO9NLqeFZvsZOsi/QTnjavCsI10O9dgiatb1u04DnHo5wIGbaFRVbO4BBsbw55dfclqfSudcu/EpMR45iovfwidqnRH+eR9a95RnxIBkHIggYlb8XLGz6bWPl759ZncJdviQKfnlcMYB/iotUyrKQ8fZsxfREActNB73aI5mMpjxAkzuXSzkUxzWRdW+CX69h7U4YbGTbohDvzxpe8iYyzuOYSEGnafc7smGKpYU5sLrs+97Ie6vi4UtyrKVrNGt9ttJEj38AJ+uPyiwb5YOpORuOgxbUV2IHHRUaRaVc74Wl6Tl1FilCvsJcdV9fC78mKA537bV9rv7ONTGbrAVkFH59W9Iq9VjGUu/hwnEQg2lQJ5QKlhVHZwYY1Ewg5btSHJ806Im9l7/HFBqB4sbuwdFhHSrJjpVj1RhDRtdStPermG7GeclKtUYKdGyqL7ANTG297WKhA/7yrlta/uiJezNeyWlyBCmUr8MJzPVBCKmAWfg5Ss0qNcggZnefZ1hbxWxHNJhZWEwJn1Ec/qXUVkVqo5jRr63jSxstBdMmowZFoCGDZRkiVCCbaXUHFgmGEEHJ8pBFN5WfokKPqFEElDXWW+Odtz35iqEfuz2Kn2PGZ1HNj5U5HjrJLWd8Uw3cLh9lmQrCXicHpMny9O9ANpqVm2M20tSf14CsE5ruQcbZ3i0njb6jKZDKONJmdVivp0RH/dMX3eXnsUErsPs4yIDDTp29dvqwQo6mMQOv1ifvIBs6mSjcKwuoq5R7BMsc16KX1vV6aFvarcw6BM8hqSQhXCWgJA1EKF2iAFUQkBsxfSHDIoP+R5LjO65HGAItLgfhq1yT6chLms2zN+kpjLcSmRmtXajs9rjK9kVD1BTlg6TCNc+q3GGXU+jLB7JnGPr9Sgysene+5c8XpsnioIvMq2GH2PB2xNOuR0OWWYlQM8WWSsyI1bKc0ZpJCfqK1sJ43/qLvqUNzIVK4XR35gAuNyP/BdEHoilGmcEQSzP5KtNbuRJif+PbaMzbjhh6B1XXeyY1VAMFEuav4Y8vwCyc2+TQpQqqJ4JlQ2Rytqy3QCR/46lrE60+0urPaYbSxULEdpunCjs5zpnwgIoHBDn/y8oqplrYThp8pqk/6FfezZSKkmzpP2AB/zHeWKNrJLO0OaVMpnpEOLtvsE7mk48xoSfSonBXo5UY1xznUM6k8hZrnvfy3GiIPZASfYgQ4qyV468FdZi/9Ld5D6BUnYAr+TYqSEfoL3R+W4aVf3vt8hw9bLmQ7WISal5nwptd0TaNqap2pIKxTeagUdNfAaxRNaBTYU7ydVcY9x0GCsbaYPLdZHTJAoyD+IqcNX9DOvp2wml7/hPlh8LbGdjkEyv51+h1KpG93yCdR5ki9+aSnl1dWTX03U4HG5zHnG3u8pfxgWei3deMucXCN/oFrJf40QFbO84V8CRkyKcFKV8MV9hcgR7V4QTNDNVRS6oWzLi8xJL9+9Fq6C0m+Mi47FRKaRVtFCUqUUnld17k9k0Hb1mshBYncIVaXoQY+4vjPcsoEcn60MDubhGTXIIPzYD9q+7EtQQ8OlTSAXoxOHkMu6UVb+0FlNaGqGDsgZrRRzIAIpororBIEWOKCxxpfh58SRoGcbHW7gIJD3Z2SWY3YQhKZBbSX5MAyqdrjMsFvvZjTOxVkTqspS102FFySVMS4y0iZTWG0pxt8B71eE4UR3BUkFh0MF/XQF/ksg+2HZpK/3SAs4/XH7a8jM7HXXOUWa88UMq49Zy5tFTIER8+Jao3eM5Cw8vt08IWSqTQSY8DLH61BrmlI/3ulzOFQFKhCV/uIzIvj24BIyyzudrIEvIvzK/klVSHwZWyDF+zJQlNBHvFEQ2E8VtrZLpp5Pnq0BK/+0af9lANRQP0FQ6RhVNpzT1k4UL4NEmC/AKWtxjS0iX2cCLjl56p2hU2nuloUXixJvkI8SnfeiZFNvu+FK+GR3pZXhxNsT/H5yKl/ZjtonBX+C4fjKoTubqZ7TGu+lp9FniENgcyKwkhY7vkpz/wigGTKIP5UGl7k1V2b+uS6/HfP8EcA1HeZlNFrCrC1kmnyew3SS/VHDZ9jPc1CwkGPsm4usHnvChnkw2U0VPJXaExgO8j3dBS6/tHB/+prwV/CipHnjWJpinzyw72I/UYBfj5TxOEzxq72GnxTqUUZRDjRaMN9C6wnnuGR6YcKxebebnCJ1GY9glZfbRA6ddbT0fCEhiW4aSA5G37cpK1gK9CiqfVJ3/abqwBrl70S4RDBQgFzXs6QkQ7Z/O6aw3zfVyu15k5ZUJbvAXkraO+co+fxyfVPpJFKTN1qNe0EOQtWdv1nikcpTSy+Y8+G6o7qjoXBvn+wQ23Hjp8dkPm37tZKKvFT1JLaC/2feGq4ihMi899eTow0nNaKVG1HRyhaGv18X9XfCzjQQBUqox8uvGtw8I1jcELnfoOv7CzPiw6JX/X0ahM8TCvUZ5v4NWi4HcWxX+mMhH7lguQUjHSyKuI0g3Q79/h/wVIiE6fdXeMfl1IZk8yAKHKa5eSie3un5n4DvUivvOaWHaCmk3yqfOA9sIeJqJEUKD8XcmN1oDvxclp0wXRrnUKtVbn8KXnswaJ4XlNBqTPP6zZ5OFrzbSRPqLGxASTHCwWFL3cUQzNcCRUvhSZeShJm9MMNsvjcplh+EIkTzJoh0R8QKkj8PavYThl7cslN2Cq0wzK4kqb1AhuE5CS5T0Vpwzy1nI5achKsWOQ066C57TNsNjwPQgNuXL/9svXP3G00x/i7lVTfSmdaMOFUxfORyHZXZsqOPxmIuRjwtLE2K7MJeUJfiW8sB0b4aDb2LisGySJxRxBbw14LuHoecDgVTTzEiEbbhJoYs/ctXknVXYXTc7XSevdwe0fLzRs9sLCpCaauFtMDXB7m9FGQ8pFvG4mdQ0NvBMr7kRvSSWewNpDdA7/+JD1kNunoH2PFtWPQl5Y9MobqoMPnro93a8hr/RI6F6lfVbrHJaVqUx0pXeuNhEGOQZ9RvsFNDmzYfiYLOsRTkBa2TaF1Q6dFsAgfJwXLSabygaU7KsuNFAKK/k+DG+l8ZSO3LN4XjedBc/3e8odnmfq+Ihcxx5wuueaTPlY9nfztOW6iZuJJ31tQa4e4S5WMQpFT49a8teovE+b+bZUgJ7rC0FbM3qXerEGG5YmGSixxXUgmmhnyWVHgUvuzVLiIszvMXRzH89wsltNEeeNExL4hXvalwWlB8RISLHbqu0vxIFJKsj6801gbFeQzJvRDfWI/eImPqpxQIKrkpKSJjNerowtaKpxLPJBEmNU/N/+FckPKd3LD59hV45Ssly7GDVn8I6pnRhuXE8Nyzd5qAMUE+KvAVXv9J//TerDoP9+Puvc2cfDL90ww0IDYZiqnlAJTuSXo5h1Hk7Uh6oCZBdpyZ6IjweU573rVXP3MN3/XA3VvezUoAXTbAQOJvaye/ckPyX5s7k4Yq2k/SbKSf0KkYE568QnrB0N2lkq3GtDEWaMLYr84NwyxIOq64bPQ6ug0fmbPdSnKPa3IVZMtIKM1pfXWTldmcTYTd+6dje2FXr7AIRQsVi0S8KK47AWDR94nGnU5mhTlR2ySyP8feT4RMBIZENwLYH2d4FKIG3Y2inuSnGMd8mHpcKy+Y5Mmep2+Bwslfgqm4gwBr8SAvFyq9aTfHx0wtvhF6KZ6vxgnFoTEcQopHu/OGvz9GzXtj9TDa39sRoyOWG02ueAOApRIC7D6Jprx7T8SP1TpZE5btyjxU06zigrtuDooBGFSzfHMPCdw1hJb9POpOQlxGGx48T8Ol3+iaoDhzLwU9BGMUv01RMMvT/hr5ZmkPk8wfbcaNYqjxDROHu38s25h6XCgvd5a8Rx55HPRjzR/vxrRIpXijjTBgDS8nvTc+3A7EqmPpeqyUSTfJ+co51pAXwV2sqf8iS8uZiIG3hwsvp8ucvbZGMNfWTuzaaqh7+/S0wP6L5NLulxdFZ5uALyc07L6EPyFhTQ0am9xq2wWAk1WCcATt7Qb3zLng/XujNe2KD0JaOTVPPFDnbBCLuoyHwaMG/NjgINKLdGwb2Fsn63cwLS7g5IerD3/RVmD2KGnL+BSLYkaIB3BgaRjxZCqfwqILEqDPLKYk3xsTqOhB2hIZ/JBbSBo/cqxYrlJ6RIY3IYx8TbG4hjILa77l8nf72BJwPnA1BhL2YBQ+6RqOCasjl2A46hM2pgFAWDGl2YiNS3yi5/Gjw16vDWlcgZqugaPt9vbi/l7EOSctNvsQTUkPqut2MkkJfjO2g1ccTP0rK1C+l98fdG4tDt533y2BPdUtjwHchLEUYFBOubf8wmzCHQ4PliCG80lMPvddOmergikkaXKhR996OOhSz0ACBfnjO9Rze92g4JsDg/N1MVv8hyIKnRXVBWflaJjf2JX7pje4Bcrg8PLXkVC0lgTM87gTLE1hf9u+AVhqT3sXrYSAEUmVTictQCRtPYop5qig8KuDVsBBS8TJhwecACcIDm/Xp8xmrsecJAAcPq6Hfg4mwmUOIEyKWSagIu2qkJCaeBZKwmMTiPRqN8iywqa5KpGwUaEvAdC7ChgMb5sqcc3OietYbP7gRcWPceSF7gPw0Q2zi7t/2prLojSxtAmswA9jBOOF3vchln6t+Y1TYjbUedhCF7FctBPxsppLVlye7SCG9cx5LzpYHFgA77krN5l+kXHucawu3xex5WUdtjYtCFO5y9qyADE8EP70/Q8D/ftIdr17qK3AQDIMslJV0dNv9gCT7ep8ABxEio4xKUPqSDxLhihBYEqN6L/O5/8VWkrM9be9lebbj8/BSBu48O+a408H+zitIQF/BZL1yxjLRtZBxZb8zZhB+I0WS5qft/fY/iXhoMEGQJpnBd2UVpUgfYiQ5lfmyOZv7iSJFbtjIlP95LI/GN9pPgKCYGKamM0oLPPeY5RekkMkEiChqd6jqTYm1Uw+0qPKeFjj/e43nZgKMX+VQzow2hlUo9lp8H4abF/liCG4wXWADUtchyuZMLva48Ey/rq8ISowQbTlwH8KRI4S8l1092GwYuhTOedz68BaTm0DCEqNoXulJCn7NPUb7DkZChk4xsNDErv0jpTVazfV+J/DVMg0q/6VuonCpS82Gc+AFoI5WVf23+I8f2pRtpgbv9DFHerbHLGEA3xRKGM6Ng+tLgpcKSBXQH4ZUd1jywhwO7rIk2Zed/bukHPv7GI533AJp9MCT64mTfjb5rnrxP8SgOHi8c1Xa/fooOSvKPLxae2TGTyfs7A6EAZ4l3/OQTuoIwvbbm+BLTS+CQTTF7v/9X+p4F5Bs79BCDx9zcR5VB8ueZ/0NEqHYLfS4QOvWE//DnaXzQ0YBkf8HS1Y8ndgKgnCQUg9vM5kwbeywMtApOJgB3uLOArO2EmFpJqqnJvC8CF6otaVRvHa+uhVOJepDLeOYXvsm+H0YqK25T0OG88oZxdU3/uyEUn9X1aSr+6cQ9oZkcRiMjSdJvafHjlgLxza5VyNnlnHGKuPnnxel288p4sOO5xaGP2IrRvFIpEuTdXk7XmPhYr9wGBmfKlRiHgaTLv09QiOL6tQXj0+U7K1gsqoKyF+3c+4nU8W2KpvWp6iWVjW5//ZSIKgdM0QblilPl7UvkKrQVqG0qZMrqpAabgaKCb/ltD8FpXVVkUktbhdbTO5klRG49ew8Y/etaiuu/jprOR0O/mHGVvVJZzAJHfmGr3GAzbb0UmZ//QtPeDz6wMo1MZiUuw9Fd2M9t6EBTw7XRpqGPYCoqvnKOJZ/DUyScMPaoZACC0PCu2qYqfym2CMN0LAu9xWSmrmAuKKnpcWbCHIrqCziInbP0orEK9gz48y/cAEJUlRK6F1Yao5d0tQzJZE1b9eQiOxT+Io7Vo6pTVV9CigipXauR1B85ZOxOkpWFxlh/i4LMdOKUq3/PjxgMhJiUvEnb1kCRsm6kEM8G+eTSk3LABbi1ozYeTKxrUe5bzF9+IV69Gtcxf3a3z9M4ZP73QD8eJrl1vKXAWG9OpP1CpTAG27w4+TeFS5aB8iOsnEsfWIfZ2ZlszkDlngEcoLJtcWN8BHSi2BtiitS0+3LU36PzEWTYeIxjjfarwMxOEenS0zqU4XStQe3bPHh8RwAWr51Vw9ztjYPznvTffhuNv3VrfiutC/nXDrRBqnpLGTrpgXPpEm9WlbP/eTecjjOTcXos1KDFU9XKIKQZ9vBjviB//6hzVLFjJJ4iNHX3zd4oxBiRYrTrxMdGX+Oy/5Gw4hyOof8mWRWg4Q1plYC22f7xE7dtMfXx/dhHTOWoX7+FXYbxIXMGkc4t7rwrgFFKMy4U8093TH6P+pT9mHXZud7/grmINXDaKTRh5o3gbISQoRBxQ2aF0ffv0V5kgn+MQvGY2mmh3WteA9R/Q3Biyc1AlhGVxSw5VdktRtbQt/VfM1CwoA7pLWUOjfFAFioh4McBWec/x6IvifVdASmGYjfZqzu1uSZhax+3EYjZMZc+WEbMkRhQAW3P6F4y2Z3/5Q+oB+kDCfFW0ep5Eau3878K9lyd/lMk/0X70rRfrrWn6TUI1MjOpr+bdnM+QvoZ0lNLgytaffj7qEah2xZtvR4pKuTxCI+CyOwCmz1QCV0fzB4XyGSf17Ykl7BsGJH5zO2Gb5do939fhEdbvlDv/wBP+ZG4lsPYhn2hAfJyjH15i9ffCAnrY9gSEQA+icT5sQzr4iuU766Ba2q8qgB2VnT0BRmnwmyZ2wUNtlzVMKYAykeTeeTEjdVRFEvJvRtv/JXNMyfHCsVSlROT/83a/hNcP+3sTs9+83SX+/cIjITRhbVuZGvw2yroA6d4xB7w2p8l4wYP/tUmmxOiOvaSNccN0WmCPsj21DXXEbuyzWct/O0mzPLGQpdJWzBD+mR/5/fZFBhHdxUYc4xINj+8EVJvfamdxmoRQjPRWMSc/DiCup35bpe5AuSncGJaWa3cxGl6v1oIT5mZ/giiLXpMuxvx8yYe9oBWWebqprJNF1hKV5bpzoaO5h+axQ1ocIVBW0DYnsL6TDlom4hwKzlowKUK8qgIO1kXrU8SpOjrmifQXKshAhRGlOnrnrDNd56DsIr8jN8RZX7kEVdRVeDKzZcgtTmB/rnjcIXvXQ4FAV60StW3GoWokh14a+y3rOz5kcvTIe6EL1TjjIzogEy47Ipm69Okv09oqHRyPrqYK2tokYDPWpNo2uvBWJddWm+7R8BnHHJxGvy8K9mD0vKuEuHtiztvgBUS5k94Hq5/TQBFyOigeRS+HA+9rI75sbH6FHxvKwmnloeXpdmeOn/1sv/7ex2GDQSmVfsjS3l2S4FzIBQQT3GeRtgz0Lk58u5CA+1T4YMWX3Fr1BMezbbxwtZIP/H5O2M8FEeLdVTnn8GyoQKiZx/NMQWbjTJ7awrV/QACmgQJ0tZwHFVemkJdOMsGjbDspTZRzmlMC8HQTBLPcYHogow1dIvCQwacOj42yCK378X/PAAm8w/ahOgyTdpbxkFeEJSzVIBgDkKk8vGKUTFraLROuBw7UVs7iW4Yu4PRedoe96uo76S612mwBSfHL79JJ1i+nYGA2V2rHApRfK+slkKjRduTfmCP7bvknTa4rN7y9KAbyoPPO4zd4yUTMHq/flLFNL9IIwoTHN301U/0WosGAL+XpRDfRr3sUG7BKxP8RueKbWqGIHiC6DAsY4rG9fl5i+AQvM0IfQB3C0zosqV9C1YHO6WA6Oe81fY0y7cuebJ9B+2aOOvhXkbxNRQcU//sWJ3QLJi3BIb8C56GEZXwmmmVTaoaclm+NUuQFqwhMOhhGqZa9X2iGDqYFQKyQ1Kj2Gxc9BVSVhPccbi26jh9cA7Gonp2qKx1czBbpax7t4i9fkzuJe2lb8q92cI2YIv6vTq1HfTmZtMeJOE5Lv/WPZuPI3/0IysLtUn9sZ4+RLFpDHwsuZPuSblFP/MlhMit3F7yY/SVRAPHwD+lZHWHig405iloZbNR76r4WmZCa6ImOj76Vkmf/K/pL3WNs5B5+hOJhRQgXCEjfWBEiQUxUtsTauurUielX0LqbdeWa3YOMTrBqu7DFlXOh/w/WSGPDKZc/atyzMmbcnXnv4VrUSJEhiQXm87A0nK5GcaKq2UdQ7rfqmm7CB9vK3HGuxn4pauUhEhYdA9lP84ugr1VkIcUUy/jS0lWOjhibXdyKY4Bj2JXDHMo039V67VBVxkQMuZo2+f7vXBzjadnGeJCVchU//2b1G5ByzHTqcqBby+/2UUuSIlHXFJEsZj7uPv3WZhwKjUmFzJyGOpHW+2RiGN+X8hcd3gBarZ6HR8y1O/TRBifX3wW/tV4li7viK6r3jkY0LPdlg7KsbOrKyk0ZL8TO0tH7d8iK3bEX6cVK3VPCk0YqehkESiY9ENAoayhVdD8r6mANWwNQc0gGCutl1GZVI04lrAOIvJugLLZVlEeLddTbvWjYYIdnRPToOHeY2qCAm233fWSF3peGe+hSp0bSJR2JYDniarqn7reVHoqcPObAf9qoooWGHE1zqRxA2Ib4yvjNv3bSuOsuhZVn3MGvFCAvAIcwHvu/b277aXJdv97KNCodykDu4z60GHfHbFWWaFJPTz4TBMrVcmibVzGIOzUK5RNgsyaFvMr6alLzrJlIRiiXlb6Llk5Djl+Dn9kUJI68tIZXqp6z+wk5yQGFHxUFEaaheAX8Aq7nxjzOGLR0MRWhB+8SggqAbhoGNO+MsZi9Pq5ppC3QOBAwzHJ/bVWZJU9xlCOYkEvZDdMc5EzEMJwV4gD0tg2xrqDoiOR1mgUZ3Qt69KG0ZK4K8mKlMA4osbJYdNtys9qmDKrPSIzvXM3O/xqHeddqFHu+leE4hF9W6lmiIbzUPq6G8GJF8RY1T1vdqq0lpIctagCGXkd6Ev2oeXb+r80ys3GAttVDa7xOoq2Xku2S6uk0UlWU9AFTjfcF1G+MUfMVI9p2GdP19yFhipngJWS9JvxBShnCx/dXpWWCtZfR0cFcjF0RiceLfLZUd1/Yqp23cpoXgo+VZ1X/5a6+VdXJYeQ7T57KNwF6KuG4NNngKNSI4ieR55BUcDpQnt1CGw4IY//3L7B1Ebhf3cJ0269FwpyiUO3myqrQT+H02aQ2DxyTZKcOwj22yphbuJTKY8gj7NjhLIp0Nfa+M8l6fcRedlDLAS1ce0lFbZINnpmOckR67Z/pt7z8GwW30828zT+1sRUAI8gVMyoKAr0ZQSzqXYYnc+613s2BD1SbMOqWnzZgROVD4KImL/Ks7zq44QBkWVWX+SMZo+9PYK8LP1YIarHepILDHOFPu2rPiM9gRG6XONjM3pm+GCY2A6kbZCgm6jFathJhBQWCWU0oNbX2KHr5To9NivFgP3MiR3//n7HL6qnrDLGHCjX/pZpz6JxEa1nxjKX2wkc148nFR9po8qAbMYuXqqqdTN5p3LpReqvEBlkq0GAaKB8ctcjpND44veLlZmdkw/lFF39DjyHpuTvg2T7XXyKhMRA4cPMnjYtpYWlX45SPJAx79ovFMrN4THVF6sA6fQ8GLlGXZaY5gfbKhmAvAqOKakpodZWNbXhEX9/us2I4PHShTQNojqfzvYYMTkuOtQYKns3Oe/iIOxO5NwFQopCbt971wvkBWFvrTjkEPg5b5sc4B82regL58VD5/A5pccJ+dMKteEsMjL8vDdOyASN0JX9nN36NIez3QO76A7M4Rz7u+oF/+7eYT5tLRAtPtc33kqcbkjQfM5AeaPO2BEitC8Bej1Ji3fJuVL0JNNWRydRVROu4ziQa7wnYN4gyeTM3T0+pbetxouowqoN3nLLxQa9d25Dv+1a0vzIxx8ILWRP0I95TiIBthdliW3nBS+q4l07NCIoLZoye7KVz0AKZ/4l4pXTg22Fd+ebEnCCsH4LRflxjIbMfwNl5Lf+ipa1vyid7r9JUjSPX7xwppG34SF8EYlMQTPsMGqBQrzRHOVXYPZke638qKQaSvz/30ui0ppsfTU8S0x0OA71n2rik6FEJ19Pg09jiztruZMqBzZAB/S1YoP/ViJspaOubTMIWuwPjh3nGo3DgymgP8BGipXrbBH+ENOreXAhRjv7b8/uenFYMAf94uU10nbqXZCNnzRUd5D2j0K+dP1QoM1x9/qZ/fYX0t/7IEVJUazcKI+hwOu9qrA9g5M/Jwtr83H3cV1q0jRNWR9wvdhoCp3BoqF/oQfwXVdOmJibzWxax1H+EmNtcXyQYwOKo6+XLxgFefBWBk84Yte5FJ4Sl75Q+k0jAoUUFFJwiDZsM1x9MWhMnVKWc+VyQD6exoI3TecxHdyiYZ1kdp5GinUMmbzc70C5pG/imP3bhfX/RKFnxP7opHji24SIbz5+ujT6rol7ijz1+fVqoRzCF6/H6cgmZhjPj7HVth6uYPHluCWjJoY4JmZKhuuMzy+REmVlAJroyBUw37zSiDpz5WYIM/IpmBzswUtcuhvuLnYls+SiW107Mq1IQ2GwQJd7YlTOcbQba9pt+3//WooKrgB2GR5J9i+ioi1B45a9vsamE5bat/US6PCEPnCYxN5FXRIV0XYMh5mGbY2RNhzPd83vZjOBJptxcuGNLKOwgrEw/oTq/jVRiFm6SHT0nQDWSwI4ZmCwDK7QdextSJKaCMsbpAPFyAEATgbYxjIm0Udz8M6QqVjvxyCVQUv+AuCBYCX5eNa5H8V7bQVtkmJN4zP08FL1eHuPlRFMECfYwtwNEiRlZsUy+WJyhQfx4TcbYnKnk3iSZPLg25CkSLdy+AqsYLgexH5Y3mA9Y6WowY49oXTaAlln+9ZBfKUcD/DpQtvq8+zgE4mb1pvUhKbJz/Xg3iD0zNauPbTIsj/3noDikpVYDkA6VjMcquv4T4IDimWJWxOak/xt+mGP67NjzEwjeUuxotw2eKYN4NiBwZGZmXRSgXrwLh5GC7WMIo32t1Qh54xbXR3kchx4u8q27VjBLC2kWErzWK/C+bk+zrfD5zqlOqBydbpXRaLXiKpFmouy8C4cxv4L23ynreR+90IioAnMOC6T1O8FLaQMuubbp3XV/QCgzQzMGLoDd72O3tzhIXUm3//fO5gpnc+BAXTZXcFoydqwsRjYa/kUT+y9y+lLfGjbqkLfvgDO7UkNVPY950Kj5rb8wSKbVcq3X5tOmrG8qIQ6fvWPRn1uHeO5MCTPm3g2kF5oMtDPYsc2ORopG4bkRKwXB+Mc8BOyMgPvFaEinTKVALIGm6Cww1nSalAij1XH0zuK4damrB0BvAtdN9BxgUBDN0XQcZeDbm7YAtOTbya8oAKe9Hbbesgodz6UWJIDGNt3Jx+jYp2nXwf2k6uCVN0xCzgU9lmp5T90DwzK7dgOi95YaQZuea2nfark4MO1o8XlaDuTMZqnJTlnDjSRW6GeEI/RkM5gftDs9lbQs98jJPrfQ6tw8SItH5MUIkLYhQOfyk+VM5TBRO/O3Yxqw+V6BXjRl5y6f5p9qnuo7QSh4s4Z3MTClFNRchFkTYMFzZwSFqKTdVnKyclYS4XYW0ji60YeyAl1sDcdJs9gMKO1YmxNfzsTVllk69tY0AxWtDIgJVxic9I+8myfyrP9nsVW3Oftz71xNlG5+/JhukgO5W/kMzNXlsCfPrg1iknLYGfO+ImEWmly5e5vTjalyWsgJ/SC985NGMSf2KUyTxo0G/Q4vmt+QMELecBdIEUdwTXrz1EfuzRy3BUbL7b8wQDnAkZ/thIp8taLsVFHxnecHAnaPKn0iUhDgDYzbmt0mPoOI8bSJFf13LwG3lMqynxwkix76JlcZoWOyh9id+AzMlcyEIB/GJ8Hb98xbZgkH0nG8ck98oGCPT+MURla9IR/VW+cvN7EAjDR0Za5X9wNkomYGsVZ4DKvheG19VhVfpygJciRuwHw8sYa0hCX62n9ud/BaFOVPoAK5T7cbYGI2fFvxR51l6iOchuO20GG2JABNlDh2wevRQL3kZOmXSAqyetmyBHryQjZuN+zxkE1VpJhaX7c8dFrJQtvfmFab5rVguiK/LauYEKZXbXpfRMbiuVLUof+YywdiTG+bHesXn7ZUCZYngKPXiAK3P3AvEEnV6qsa230kI659CTFF4Y0uxB7+l2711dTeV2kdhgoyRlFte7zZPiSDzyR9yxcFreye0qMHk6ht/8NOQLvVJPXu9fRG9YEYVahy1uiyiCijGElo4gBcqOOwOEeQxiY0h1ZSCzY3VZrXYbQs1OfGxLsPauDefNUW4zIuY9SLxilY4exwuU6dlkeFA6thAduy3c4uAbcs17EzB8FTW7CrLIDiCmzzDcy0bcbWecvcsd6lyNgllO2COYQw3M4ItejQkKtd0zqlCOJm+TnuNuWYi0B9tC+VUFk4Tq0InCgt+prq311hhB1uN2XYULYuAmWhufKAmQbzMl5FfLMTHBqjHMwb3D0g6kOZrp2UiyEQK2zaj/SGgmr+C9M/7OOI5C9382v/AxVM5az0r0SEUdPULF1nI7CM4VWnGuP40Zbu48gpEc/QKATLYFmAwNgfqGwngei0nWnONHoFFIn810Jiu7elUop+WQ6VEWRBu56MTtKHgRWN96CSBU1uYlndbTjwcFZsQD6ha8VDbx6valgsf152D6754G0LMiVPenTwfrhVAyC3HH36K6xbco5IR7u5OOiJALm2uciW7r4nO9z6ih76ViEO+mc6wPVUSS4Ae0ka2Ngr+D5tyLLoG7/p4PVobmAHlSqCNBPBjwNHXStaaQcBN2VzKuTmCKJ53BKwKQ5CAmcWxc84MeySvqJDn90rI3l15KTpcj6Sp+RusEGQXVAWJD/WkYMzHWZ7SN/6hZzoIqw9bgKS3HCZkr5e43XlhgdRrOkkf/SEwBLUffwKdrQoqMQ8CegFHh2ZXi/8Bd4vDJXLyCcBJt29sY9zHrtbWZcQj8wZ0hiEZu982KM9OxxNDsx20xsS9tQW1Bvg6yS0L/aJ8a9TmmUtJiSBBdhMC2PbifcVsn0QsuwGkWFiybH/ikhC5yEat4F9O6GtW9GLcb5IcpxDRd3rnmnbGYyqQm+VHQfzGg5pBTcovSpBiFkXupLPNHTvOApAdjzRQcm57byeje6kJXF0KuyqQvA9hgPKO77DDRiLBnbDPHJRNFKKMgl0E0YA5cOduy4Gq+S5Y+i9/HWryDQEvmeDPZuscMkA0g1n4SyzRusOaU6PJVPLtk2i+S1f7WzOMS2/xwINs9meXhqEc8aDRAcGocyPo5DGsft1ukOkfbq9MQ/8BvxhoUPxu/DThmGYQanMSSgeRfBn9fp6PMTtjvF/eb+4l+VpbLeVq9dyZoeyT8wDQEXaLAKywAUbh6oxVM0L+lUN8niXZM8wf/WYS9GULdBRdhzEbvP7xWkuHGqjDLe1X2YeyA45/ZCw1lrxt4pjTwO6dpRo6hQPoaO5vKTh97IHLHHIBCOw58t8Vp3nglu6ny2tL7Ia0DXzIH3DE2tgFx7YhT5eTEeRMUXfmZnp91sU905sMeMsF84GodjX+42DzkgCUn5aXx7ASedK6MJbM5o9Q4FMOqDmLIYQW5ckkv1y/Rxi2III96JPPXEw1yW8t9V57BteH8XkO6jCFY/7oRgUqfqfZfLxzRy3JoOPUYaHuo5iTnAXrNXaJQqJDcmzHK/dJTC+Q6MS1lMN57rpW4Ho1TDgERtCJYumLJqPOJ64ydgXFlYtsL2I1ksshePWelg4wF94ywgU8zM/aWA06EKU3QSCvpoLQ5QaEPSTZo1iGxfxbv4LVkZKHYvTu6QLz3T6OV8wDHZoHdJDA62+QvZAOBIgNCBDvHsA1PF5SxsYNro2Mksjwbm1YslYtTDi0C63hzfhBeucHgpQ12N4sQHPjMlYd5Hp0c1J/iscqZx7MYPYALpE7fPchZIbFv8/JlYGNS8vgvRmXWSUKsre0pFXc86yu7JIB8e7I4gjtddgxPYSz4E7u8WG8U+S/Dbtavpecn6KC8pWRUe7NicTHZPKmstnChs2FXqDhxLF/z/zdmqmVHPxv61Wr+dmVHSymUyvq9dmhwOBj+qIJdrMXZJ1qtJJHctik5OLE4dvgH0Mrr4re87BLE7xxmdp7dl0gSAO09Z3eR/nZqk//SHfRONSMhqbHYAPQxiWfIxsmMZTYILx18ZUo4VYth1Oeqfn1fOv5LJ07IV65EbasX6ioGaP36dXVJgFnhYq9plHQHJYrSYUqQ4mtwDuJLuMmBPYycCGUiCHarQU9f1448oXCAAZRr4s0NGlvLy6VodTI2f9gy59JbkAZW/f16jrfvZOwe0SQbbyFlXIEJaoxzfZyNuESQWI8PCWWWSznnOZaJNZX/IAFK+E5R5cRjG6KvJbhLuK0V85csFZMq2qQCjT1XdKqa9XZ0QpNDxuOVU3VltDwFNRQS+F9Q57LxFhO7yk5Ex6b137aqkJH3C7/q72eGy7XUVIef38OQG5HMnkMOBd8zL7++mw3HPUDEBajx8ym2Rp7edUHj/ly4qF0lY/q7D2fUXith1R2hXadwdNaoBPzkhTIs9MpuOQoGnpkSxc2TRWKl0KtlAfQGNEtGbXOU8OL/DBeJJ9cck6F4zY8cVTvXwgmZdxt0jOpWP5hoKbRXIFN3ZW+ByyOBPALJERKhLj5TpXVDBdnL4/pqsth9JOCVOuJrEgjUq0PQjWLRhRXe+VzqzjsprOlN+I7ajqV4yfZ7brJ9370eTNIxJ4bwcp+qT6Bp6I3plU8+An2jbfailw76UFh82/pWSa3NPME6D3TQFoS7BFL/vFS2H6bzqtmy3To+F6/DWt5Ne9Fd9DH/xYFvyK1UPzcaHdtWvLas1EK0rbC8ivmPw0a4Px62aEb0q21OKX3ymP4CgsXl1MECowO+n9Bs9n6/bSy7QcFFAjJQ1m3T6tntdveaBMpJ/Ko43EDSXplP81fjsKyVP4KQ/B3Sc0I8OG/mHs3sKn182al7z37qMIDDvNVZu8kLCz+AQ/pKwt0rWaLy1veJvGQBY/rNZAkLvqPYf6sePfSyDRB1HOFiuwfYJFYnUXPYqpHqBrJfjPF/ePmA/aCQmYwff2Qm2VjmEenrJmpEniibpntzKm+6FPiq5o0M8B2IcBBFWMrfnCK+0K+l6Dkho6T27RrdtCMsHD4OiH4M4r/ZMCmndqLoMTqrxGpN9jfvfBgz5rL1JEqgnbGyiXzWF9Rw7ZmNqFtKFyyVDtArHRBbdMz6RF2D4UEifZEKqGpV7EMAhoDfyYGfEojTz7Nwqm+XJSOPwdiHEorJ72XNiSP29QYqZX2KiRK62bdUYmlmgS2OAujb0HKoT8exCTOUTGGknxNfIr7FqFUM3Ez0+CZ0cxTeccJwK15L+u1tUcNwQ/ejlsY3Auw80h3vBt+YRalHPBS3HpuepwHTW5boVh7uEkX8SMlnnwq0YtWnqf+JfT9E8LwqfmOg0OJT5jSt9GMIMhVSW0tvKLIrbK2azScumPM2HSv+sNH+QldXfa95nybjxCtOlcsCMaUgMR7jWFMTY1Ay8iuVPaprTixTXk06tV1ZONnX/L2j6c0mVRE+ZbsICnh7GkuMbgk0FHGU/ASirjbMYuiER5nXEMdSpAhVTXGA/6I1XIsUwtOXuo0aKBYwVDdJE1s7fDEpUKkw8ML74bCKmi4oBH9qjs8DJHfCuIIDaipqvedzXZntMYGk5CkoI3bkm0AGZraPeR5dZOaVi7PKum07zo/zjtoI42vALiqlu4mwzT1EKi8cmIcKXyLuqW04RSVHX/5sjodbp8h8sbceON8B1fYsx4G2jH5UL55a+RVjiR/wUf4tOuurkmy9wOHgFJYFKuSnL9zc5B0NRD9o2CI+fcVwgBvrKJ7QVrn1zuUpGDAraVa/hS8Um1sPKMhvL55JGjOsh+RfSh1d6CnR9oTdPkohsSuyMp6Zt54zCVQzM1+NvLC+A3KJPXMtp1LtspYgy60IwjfPRAY7FV/TZXWFaLK53V7TDrRjdOZkeRbgAlVjc+rxpL5sonp+ybGOXW9Dq52kCBVtrxZejXcVq10SO7ZvdArTsrLNh8mZ0vbIFxJv0gbGFOg3DQggw12FR3nuAovLVCSM9W+a5Lk8q/DokvMPbEHuIyyIrqXYmUYEcSVAcvJMI6tlJeVok+iQeZ0IIT6ScvKFKyFc9GQrEFBC20tcbMaScjPyLDj19dUfIIVdXpFwgsk5FZeo1sAO20Ub63VTFZ2vo6pq/now3fK9FNtLtLLDcy3LS8z83+xOtbGe79WxQy+8RcapSrqw0LQ5V7bedTH19x05w2wGgYv/Kd1HtrEHnJ8iHEOTxf+/R0fqEtZT8Ned+SAP5lB3iv/LQzB6WNwN1MeFXC+kve2cD7mDkEsrthaq4C/qdnNPTMXSgLahetIX4gh88mX+2CVt93dAU75wR3t3r7kzEhjRbFjx+CbU5HgWB/85BXpSofT0IYjHko8vLoecmIzDk0BzVnZDlmDoe7UzE6j3k/R8V71tT1RF5G6pTI5dK6lmZLrzB8uylj6cFdcZT+THl5/tE6GoUhzy4btkaRz9rMA05t+V+2BVAZ5yx8lxlQk0BmhYBF9bJL+A4ZwE8/WgkI52ws7FuFF5qtALTH7RUZmpp9+sTWdT4y8563bp51ZyJpj1oTivvYJh5HsJfRDZsaMJ5Ju5jvcDMq1miWBL+QqIvvt01kesWi3jfWK7BFjYskDbO2PP5IptKcf/ceGyRAvGPln4l2HjeLNeesvd3b8EuC4UelEOLS356i4m8gNX4xDHFdLLPxedSm4bqULCGrhIqCZFb7MzlvDLOcIzZvBBZybpjcshgBvDUsttm5QyGZcfPHyrJoLqSEh5GkoiHKjRn/3bfQfcyFHRnbv76/yPZTK1LlSLrpitEQhjRjSZON5Y4trzQXLLpDWaJp3Yq9yyek9xLpLtLZ9Hsu7eKsEDz2XzJp2dpeGJvmVZ+mFv2vq4qnseVjN/8aL00QlpwnckkpEFBPCY6nos9JYMB9ZhlZS1mVT+luntHD42vY6SdCFU4iF3TxiE6/+GZHkdDFVYVh0G0IXYxEpYgg3BGoRYShNRpmtyHWGow95N7baGU5CctOgyTsX4fMX7rM/nSaAyFSt/gTywXaisCsJs5+wa8JzZxzNL2wgr6AIa+1hz9sHmMFDX6Q2sfwW2LtWyB5Tkg4ah8M2RvsVopEXwGUNHycnilADOvmF7DMZhbCcpXmAB69bJsN79pAD4Z610bo/nP9gJc0PcUECMVST14FkmF6Gxl0XK+MDhN9XQ6wSAxVfYsadMS0XSy7iY2KwbpvmR+N5lj568nMHqyVEsaixGPgQQ5BcEEOQPF4jP1aawvkgXqE6MWmzjt0l0vWV8PDgE9xh9PzuPDyiASWzv+SpoccE7gdQHMkAcneQEcvAdinteFHbW9h0nWF4Y+OHjk/jtvU0EmCULs2Z1Puq3xy0Egq8LfM127j1/+eyEw4KnCm9MjNL+bUBvWk80RmfR9IGUOtlxRwZS4vSSumCHaXzZj/rWhJwgpDjeOwV8wt7MndoL5EAlg8cmne861qYSEsBXAnaUdl2Rvqpu9B4ajepQraSOIHdKGaHV6frneHwLhTKxMCPuzHteU45DqKuuOB641bRnAAH8N95mESHh/esFsBK4va/l/6CzWHra+Is7ud+gIBqoFqdIWU3SG5bv1B63Ziejp6ewKe8V05skfG/SH5DVPmT02h9wHWlC5wWRuKoEMqoh/02z1kfjKba+qXBoqh/ZHyOzCrrSBzNfpq7DPBU2dJVOwE1QC8Z4Oa1rpgBFTQgrmP7HhuYgcxl9OU4fPF9FLyF/qe+mUok8NN9iHGOSNio4RuJPX/DJ9gKpaXWacySv9mcktdBlfiGX7PSdoCuXF+ehVvgO2F4kay5NaLxy+wyponq6Cv0Vx0/3wT7ONb7qJydusmgxP0O5rWTi4vQ7yWKAskRZcTamb/a6oKd2CcvUJyZw3zhxA5uvY+94KyMbCZbk2QLc49YUQwKhrPrKMeykL3M/Cn8T3h5Xs/SB84Sag8uaVa7JdgiECNkNmNkNEMG2XrdgifwK1ifvIyIpmMKWqC0HxZE3tGask1eyX/TQ9VYBRyrLX7Zwd+yO4ybpJkXRM8+7CkKvCh64uG0P2bA+s86Yg/7DmQSUBA2EuAiJ1F54UaSqsCjEMU+GSjHzmGImKRfc2E9h8PS+NbPCYcyXPqoTYjOyZDlIymUzNG/YM9sv2GktJL4Bc2wKFQTO7x0UaX3Yzjj9aWSHiOeM/O7njGzj1Evof9RmeYxZhhwaWMoaSsWkoRNpc/RStRi9woDQbo5odmjc6h/AhB9kLr+IqMC+Eav0UfHKYIQpJRDVZvjzvgirtStc+tsda0W9X/QOGSUbvBpsW2Kw38Ajn8htuwVzAiK9/7xy143JRt5Fb+wylie4XmDM0Dp7pqjSNSJdEbv7E7kYk0n/mlj0bVK3gir4j/FqLcex1wyX0suJYjUjzy+/NJWsOepH1ENi0kjx2Fi4hAHfH15p5uJ0d7lwaiC64wgj8di2AYnjzCcSzVFrZQ4Z36U41O4t4oa8sTJTdJ5xqJ3xkasRuctS/CkDh6rwZd8BQTYDrKKMQqOJT/P9mHrdWIzBp7Umcnrqtno6WEEJhpxJc9M2ERuJYVoJPb3gRA0JtyHMTSUS1MSa1hWdBznYEP8kjBPjawPxEkitBvnPB0TCYCgBRKttcNLHrgYRy8FFP93x/bzTozsYHxJLcxmRGAih+cKYpXIZ6vHrism26nr2WDRluQluhgDJCDVTDIZb7HVqc5lQSrOcWcOdtsTM0npW5N4AzGAv2BP4viQxPayvnampA0thVis5CNEuHPV5svgCG2ku7kxfd7//psfJJltOBK5GH+GtekRIatKxHRKuwpgD8KG2tTKwJVJhzKBvkJJh75bf0PTwDY7b8w7CiJjJfbCjzzO/u23GwOfx5A4dcmhPfLicNm7L/wj811wLK0zEKk+EyTpgFonvpD6vY2kPa8CLVjyqtzV5uN5t1R+YSy1qkaKT4dLDxjk539+PAGkldImfbqHQkDQoZE1+C9dpPmziu4XQxPP40jsKDUUoXOt1a2OyAyNisXkXD3BSDLc6V3DjVUXX6uMDuxOXUpjctzEcvK2NFLCM/kVbcgRJG2PbgJkNI577WQJ04wf+lVRmFzVlnUH+H0orRsw+WYNLK0lLXMqm4X3yLPG/mFygw6UXJpOM3QQ/FgkvlVp2QDvt5iQE8C+9SmKfyrTBWJ1jRT0VVWyUxFDf2uEblW0hO2Pv7M63nWRe6Eqb7DQ0m9L/7Em0Dt/5j5MD/i/dS7WwRKDQ8V2X73cLtft5w4l1r8hs4u9n7hH3CovaOLiJNii+egEWja+DasRdeqDg2W8OzBEvHSommHhGR1mf8Q3k/2LPwA9WYBxU/tsE+NfN4CloqUHsaX6AffjZTRmQTjoOvhYztmKiNNCtdV+6eBm5nX0E9//THKHs91qhrg8dWlCWjdp3Kzo36Qow++MVJKvKJMY+Pc2JZkxTm7DiSg6dpe2ONSt8yZe3OlJRMAQVsq9XFoeq/GIo0OaddGO+ucgajWk3DY2B/6Oczp5LO+11IjXqUDHj4XiRZ1bUG48tKBhoaSXXuUuscpLYkNy7EJQBr1o7ErRcveSZQN/9hJKrm4279ktvHx12NqGHGYVhGpK0LJgMB1LVxht58OlGC5pncKoZM0pkwExEE+micL4rRA0z5w1jHTY3bP4TpvBgAnN4yz52x15XQ3aGZHW/k1I/KVHwZKd4qppmB6dCVx0IoRARiXGrGaW6ElpCvenP0RXSL8evlQBX0xUZeq+WAa4/AP6QjIs/AuH5RoeupwBjiVmOUHJc2XqcEK+fV+twWzIyj3CKea6JXW3/Vj3v+yI3SUWKTzBqCkI3Dm3+e8L+q+WtwBFv0Wx92XzSUFuzAnoqfNtbfhKFR5MJeBwdTc+nmqoZHlagM2pVw0TCpa1nqLTsK5tuCwNZzP2Dx3qfBrZ3EZAHOtpfRHQsUnbMN5nHD/nkDHac+bEhu7BLHXkAdLDl32CTSfmTbMHIFLeMVUG9ER1prvgb6ZI8NfBWit7/p0qe5CFb8C3OjasHJi2wyKqxCzotmEldLAi9carqYwiEUQIQeNG52yvObStI/I4uy/qn0oP+9JBLYnfknJYYhwmrAmTeFfaCSlRyPiXen9nXsig3t7WwjXdruD301P3w7edaf6PIuxepasJnttSZDkpdBuViWTEFB5c5eHkrNlHS0EcffFyfQABCjsyLtJ40/+/H+A1OvyDP5sPQkoHg1UbE2C55M9rGEGNxoMXoOH61q0ADYRj3EzgYvAtBF3iNs/7yNyts8bXOPLgmwXAlTxh+kE8tP7QFBZc/T5]]}
}
local function bytes_to_hex(str) local out={} for i=1,#str do out[#out+1]=string.format("%02x",str:byte(i)) end return table.concat(out) end
local function rebuild_cipher_hex()
    local acc = {}
    for i = 1, #cipher_fragments do
        local f = cipher_fragments[i]
        if f.t == "b64" then
            acc[#acc+1] = bytes_to_hex(b64decode(f.d))
        end
    end
    return table.concat(acc)
end
local CIPHER_HEX = rebuild_cipher_hex()

-- Integrity constants
local NODE_CIPHER_BYTES = 19152
local NODE_CIPHER_SHA256 = "bd55722b47adae6b62034f597b7dcb0961e68546a27a76ecf0fcec311452e6bd"

assert(bit32 and type(bit32.bxor)=="function", "bit32 required")

-- Helpers
local function hexToBytes(hex)
    assert(#hex % 2 == 0, "odd hex")
    local t = {}
    for i = 1, #hex, 2 do
        local n = tonumber(hex:sub(i,i+1), 16)
        t[#t+1] = string.char(n)
    end
    return table.concat(t)
end
local function toUint32LE(str)
    local n = math.ceil(#str/4)
    local v = {}
    for i=0,n-1 do
        local o = i*4
        local b1 = str:byte(o+1) or 0
        local b2 = str:byte(o+2) or 0
        local b3 = str:byte(o+3) or 0
        local b4 = str:byte(o+4) or 0
        v[i+1] = ((b1) | (b2<<8) | (b3<<16) | (b4<<24)) % 2^32
    end
    return v
end
local function fromUint32LE(v, origLen)
    local bytes = {}
    for i=1,#v do
        local x = v[i]
        bytes[#bytes+1] = string.char(x & 0xFF)
        bytes[#bytes+1] = string.char((x >> 8) & 0xFF)
        bytes[#bytes+1] = string.char((x >> 16) & 0xFF)
        bytes[#bytes+1] = string.char((x >> 24) & 0xFF)
    end
    local s = table.concat(bytes)
    return s:sub(1, origLen)
end

-- XXTEA decrypt
local function xxtea_decrypt(cipher, key)
    local v = toUint32LE(cipher)
    if #v < 2 then return cipher end
    local kraw = key
    if #key ~= 16 then
        if #key > 16 then kraw = key:sub(1,16) else kraw = key .. string.rep("\0", 16-#key) end
    end
    local k = toUint32LE(kraw)
    local n = #v
    local delta = 0x9E3779B9
    local rounds = math.floor(6 + 52 / n)
    local sum = (rounds * delta) % 2^32
    while rounds > 0 do
        local e = (sum >> 2) & 3
        for p = n, 1, -1 do
            local y = v[(p % n)+1]
            local z = v[(p-2+n) % n + 1]
            local mx = (((z >> 5) ~ (y << 2)) + ((y >> 3) ~ (z << 4))) ~ ((sum ~ y) + (k[((p-1) & 3) ~ e + 1] ~ z))
            v[p] = (v[p] - mx) % 2^32
        end
        rounds = rounds - 1
        sum = (sum - delta) % 2^32
    end
    return fromUint32LE(v, #cipher)
end

-- Rebuild + integrity
local key_bytes = hexToBytes(XXTEA_KEY_HEX)
local cipher_bytes = hexToBytes(CIPHER_HEX)

print("Node cipher bytes:", NODE_CIPHER_BYTES)
print("Lua cipher bytes:", #cipher_bytes)
assert(#cipher_bytes == NODE_CIPHER_BYTES, "cipher bytes mismatch")
assert(#cipher_bytes % 4 == 0, "XXTEA requires 32-bit word alignment")

-- Optional SHA-256 check (requires hashing lib; skip unless available)

-- Decrypt + execute
local plain = xxtea_decrypt(cipher_bytes, key_bytes)
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
plain, cipher_bytes, key_bytes = nil, nil, nil
