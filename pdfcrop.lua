local ffi = require("ffi")

-- Constants and Defaults
local PROGRAM = "pdfcrop"
local VERSION = "1.42 (LuaJIT)"
local DATE = "2025/01/27"
local AUTHOR = "Heiko Oberdiek, Oberdiek Package Support Group"
local COPYRIGHT = "Copyright (c) 2002-2025 by " .. AUTHOR .. "."
local LUA_PORT_AUTHOR = "Li Ruijie"
local LUA_PORT_INFO = "Lua port by " .. LUA_PORT_AUTHOR

local EXT_PDF = ".pdf"
local EXT_TEX = ".tex"
local EXT_GSOUT = ".gsout"
local EXT_LOG = ".log"
local PDF_EXT_PATTERN = "%.[pP][dD][fF]$"

local MAX_PATH_BUFFER = 1024
local MAX_REGKEY_NAME = 256
local MAX_REGVALUE = 1024

local options = {
    help = false,
    version = false,
    debug = false,
    verbose = false,
    quiet = false,
    gscmd = nil,
    pdftexcmd = "pdftex",
    xetexcmd = "xetex",
    luatexcmd = "luatex",
    tex = "pdftex", -- 'pdftex', 'xetex', or 'luatex'
    initex = false,
    margins = "0 0 0 0",
    clip = false,
    hires = false,
    papersize = nil,
    resolution = nil,
    bbox = nil,
    bbox_odd = nil,
    bbox_even = nil,
    restricted = false,
    pdfversion = "auto",
    uncompress = false
}

-- FFI Definitions
if ffi.os == "Windows" then
    ffi.cdef[[
    typedef void* HKEY;
    typedef long LONG;
    typedef unsigned long DWORD;
    typedef const char* LPCSTR;
    typedef char* LPSTR;
    typedef unsigned char* LPBYTE;

    LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY* phkResult);
    LONG RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, DWORD* lpcName, DWORD* lpReserved, void* lpClass, void* lpcClass, void* lpftLastWriteTime);
    LONG RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, DWORD* lpReserved, DWORD* lpType, LPBYTE lpData, DWORD* lpcbData);
    LONG RegCloseKey(HKEY hKey);
    unsigned long GetCurrentProcessId(void);
    DWORD SearchPathA(LPCSTR lpPath, LPCSTR lpFileName, LPCSTR lpExtension, DWORD nBufferLength, LPSTR lpBuffer, LPSTR* lpFilePart);
    ]]
else
    ffi.cdef[[
    int getpid(void);
    int access(const char *pathname, int mode);
    ]]
end

local function get_pid()
    if ffi.os == "Windows" then
        return ffi.C.GetCurrentProcessId()
    else
        return ffi.C.getpid()
    end
end

local unlink_files = {}
local tmp_prefix = "tmp-" .. PROGRAM .. "-" .. get_pid() .. "-" .. (os.time() % 1000000)

local function cleanup(code)
    if options.debug then
        print("* Cleanup")
        print("* Temporary files: " .. table.concat(unlink_files, " "))
    else
        for _, f in ipairs(unlink_files) do
            os.remove(f)
        end
    end
    if code then os.exit(code) end
end

-- Check if os.execute was successful (handles Windows boolean vs POSIX exit code)
local function exec_success(ret, kind, code)
    if ret == true then return true, 0 end
    if ret == 0 then return true, 0 end
    if ret == nil and kind == "exit" then return false, code end
    if ret == nil and kind == "signal" then return false, -code end
    if type(ret) == "number" then return ret == 0, ret end
    return false, -1
end

-- Execute shell command with platform-specific handling
local function execute_command(cmd)
    if ffi.os == "Windows" then
        -- Wrap in outer quotes to prevent cmd.exe from stripping quotes if command starts/ends with quote
        return os.execute('"' .. cmd .. '"')
    else
        return os.execute(cmd)
    end
end

-- Quote shell arguments for safety
local function shell_quote(s)
    if ffi.os == "Windows" then
        return '"' .. s:gsub('"', '""') .. '"'
    else
        return "'" .. s:gsub("'", "'\\''") .. "'"
    end
end

-- Helper functions
local function print_version()
    print(string.format("%s %s v%s", PROGRAM, DATE, VERSION))
    print(LUA_PORT_INFO)
end

local function usage(is_error)
    print(string.format("%s %s, %s - %s", PROGRAM, VERSION, DATE, COPYRIGHT))
    print(LUA_PORT_INFO)
    print([[
Syntax:   pdfcrop [options] <input[.pdf]> [output file]
Function: Margins are calculated and removed for each page in the file.
Options:
  --help              print usage
  --version           print version number
  --(no)verbose       verbose printing
  --(no)quiet         silence normal output
  --(no)debug         debug information
  --gscmd <name>      call of Ghostscript
  --pdftex | --xetex | --luatex
                      use pdfTeX | use XeTeX | use LuaTeX
  --pdftexcmd <name>  call of pdfTeX
  --xetexcmd <name>   call of XeTeX
  --luatexcmd <name>  call of LuaTeX
  --margins "<left> <top> <right> <bottom>"
                      add extra margins, unit is bp.
  --(no)clip          clipping support, if margins are set
  --(no)hires         use `%%HiResBoundingBox`
  --(no)ini           use iniTeX variant of the TeX compiler
Expert options:
  --restricted        turn on restricted mode
  --papersize <foo>   parameter for gs's -sPAPERSIZE=<foo>
  --resolution <res>  pass argument to Ghostscript's option -r
  --bbox "<left> <bottom> <right> <top>"
  --bbox-odd          Same as --bbox, but for odd pages only
  --bbox-even         Same as --bbox, but for even pages only
  --pdfversion <ver>  Set PDF version (e.g., 1.4)
                      'auto' = inherit from input (default)
                      'none' = use TeX engine default
  --uncompress        create uncompressed pdf
]])
    os.exit(is_error and 1 or 0)
end

local function debug_print(fmt, ...)
    if options.debug then
        print(string.format("* " .. fmt, ...))
    end
end

local function hex_encode(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end

local kernel32 = ffi.os == "Windows" and ffi.load("kernel32") or nil
local advapi32 = ffi.os == "Windows" and ffi.load("advapi32") or nil

-- Windows Registry Constants
local WIN_REG = ffi.os == "Windows" and {
    HKEY_LOCAL_MACHINE = ffi.cast("HKEY", 0x80000002),
    HKEY_CURRENT_USER = ffi.cast("HKEY", 0x80000001),
    KEY_READ = 0x20019,
    REG_SZ = 1,
    ERROR_SUCCESS = 0,
} or nil

local function check_executable(cmd)
    if ffi.os == "Windows" then
        local buf = ffi.new("char[?]", MAX_PATH_BUFFER)
        -- search for cmd, appending .exe if extension is missing and it's not present
        -- Note: SearchPathA with NULL lpExtension will strictly look for filename as is,
        -- but documentation says if we want to default to .exe we should provide it.
        local res = kernel32.SearchPathA(nil, cmd, ".exe", MAX_PATH_BUFFER, buf, nil)
        if res > 0 then
            return ffi.string(buf)
        end
        return nil
    else
        if cmd:find("/") then
            if ffi.C.access(cmd, 1) == 0 then return cmd end
            return nil
        end

        local path = os.getenv("PATH") or ""
        for dir in path:gmatch("[^:]+") do
            local full_path = dir .. "/" .. cmd
            if ffi.C.access(full_path, 1) == 0 then
                return cmd
            end
        end
        return nil
    end
end
local function search_registry_hive(hive)
    local software_key = ffi.new("HKEY[1]")
    local res = advapi32.RegOpenKeyExA(hive, "SOFTWARE\\Ghostscript", 0, WIN_REG.KEY_READ, software_key)
    if res ~= WIN_REG.ERROR_SUCCESS then return nil end
    local hKeyGS = software_key[0]

    local ok, found_cmd = pcall(function()
        local index = 0
        local versions = {}

        while true do
            local name_buf = ffi.new("char[?]", MAX_REGKEY_NAME)
            local name_len = ffi.new("DWORD[1]", MAX_REGKEY_NAME)

            res = advapi32.RegEnumKeyExA(hKeyGS, index, name_buf, name_len, nil, nil, nil, nil)
            if res ~= WIN_REG.ERROR_SUCCESS then break end

            local ver_str = ffi.string(name_buf)
            local ver_num = tonumber(ver_str)
            if ver_num then
                table.insert(versions, {str = ver_str, num = ver_num})
            end
            index = index + 1
        end

        table.sort(versions, function(a, b) return a.num > b.num end)

        for _, ver in ipairs(versions) do
            local ver_key = ffi.new("HKEY[1]")
            res = advapi32.RegOpenKeyExA(hKeyGS, ver.str, 0, WIN_REG.KEY_READ, ver_key)
            if res == WIN_REG.ERROR_SUCCESS then
                local hKeyVer = ver_key[0]
                local query_ok, query_result = pcall(function()
                    local type_buf = ffi.new("DWORD[1]")
                    local data_buf = ffi.new("char[?]", MAX_REGVALUE)
                    local data_len = ffi.new("DWORD[1]", MAX_REGVALUE)

                    local qres = advapi32.RegQueryValueExA(hKeyVer, "GS_DLL", nil, type_buf, ffi.cast("LPBYTE", data_buf), data_len)

                    if qres == WIN_REG.ERROR_SUCCESS and type_buf[0] == WIN_REG.REG_SZ then
                        local dll_path = ffi.string(data_buf)
                        local exe_path = dll_path:gsub("gsdll%d*%.dll$", "")

                        if dll_path:find("gsdll64.dll") then
                            exe_path = exe_path .. "gswin64c.exe"
                        elseif dll_path:find("gsdll32.dll") then
                            exe_path = exe_path .. "gswin32c.exe"
                        else
                            exe_path = exe_path .. "gswin32c.exe"
                        end

                        local f = io.open(exe_path, "r")
                        if f then
                            f:close()
                            return exe_path
                        end
                    end
                    return nil
                end)
                advapi32.RegCloseKey(hKeyVer)  -- Always close, even if pcall failed
                if query_ok and query_result then
                    return query_result
                end
            end
        end
        return nil
    end)

    advapi32.RegCloseKey(hKeyGS)
    if ok then return found_cmd else return nil end
end

local function search_registry()
    if ffi.os ~= "Windows" then return nil end

    -- Try HKLM first (system-wide install)
    local result = search_registry_hive(WIN_REG.HKEY_LOCAL_MACHINE)
    if result then return result end

    -- Fall back to HKCU (user install)
    return search_registry_hive(WIN_REG.HKEY_CURRENT_USER)
end

local function find_ghostscript()
    if options.gscmd then return end

    debug_print("OS: %s", ffi.os)
    debug_print("Arch: %s", ffi.arch)

    local candidates
    if ffi.os == "Windows" then
        candidates = {"gswin64c", "gswin32c", "mgs", "gs"}
    else
        candidates = {"gs", "gsc"}
    end

    for _, c in ipairs(candidates) do
        if check_executable(c) then
            options.gscmd = c
            debug_print("Found Ghostscript in PATH: %s", c)
            return
        end
    end

    if ffi.os == "Windows" then
        debug_print("Searching Registry for Ghostscript...")
        local reg_cmd = search_registry()
        if reg_cmd then
            options.gscmd = reg_cmd
            debug_print("Found Ghostscript in Registry: %s", reg_cmd)
            return
        end
    end

    options.gscmd = candidates[1] -- Default fallback
    debug_print("Default Ghostscript: %s", options.gscmd)
end

-- Argument Parser
local function parse_args(args)
    local input_file = nil
    local output_file = nil
    local end_of_options = false
    local i = 1
    while i <= #args do
        local arg = args[i]
        if not end_of_options and arg == "--" then
            end_of_options = true
        elseif not end_of_options and arg:sub(1, 2) == "--" then
            local opt = arg:sub(3)
            if opt == "help" then usage(false)
            elseif opt == "version" then options.version = true
            elseif opt == "debug" then options.debug = true; options.verbose = true
            elseif opt == "nodebug" then options.debug = false
            elseif opt == "verbose" then options.verbose = true
            elseif opt == "noverbose" then options.verbose = false
            elseif opt == "quiet" then options.quiet = true
            elseif opt == "noquiet" then options.quiet = false
            elseif opt == "clip" then options.clip = true
            elseif opt == "noclip" then options.clip = false
            elseif opt == "hires" then options.hires = true
            elseif opt == "nohires" then options.hires = false
            elseif opt == "ini" then options.initex = true
            elseif opt == "noini" then options.initex = false
            elseif opt == "restricted" then options.restricted = true
            elseif opt == "uncompress" then options.uncompress = true
            elseif opt == "nouncompress" then options.uncompress = false
            elseif opt == "pdftex" then options.tex = "pdftex"
            elseif opt == "xetex" then options.tex = "xetex"
            elseif opt == "luatex" then options.tex = "luatex"

                -- Options with values
            elseif opt == "gscmd" then
                i = i + 1
                if not args[i] then print("Error: Option --gscmd requires a value."); usage(true) end
                options.gscmd = args[i]; options.gscmd_custom = true
            elseif opt == "pdftexcmd" then
                i = i + 1
                if not args[i] then print("Error: Option --pdftexcmd requires a value."); usage(true) end
                options.pdftexcmd = args[i]; options.pdftexcmd_custom = true
            elseif opt == "xetexcmd" then
                i = i + 1
                if not args[i] then print("Error: Option --xetexcmd requires a value."); usage(true) end
                options.xetexcmd = args[i]; options.xetexcmd_custom = true
            elseif opt == "luatexcmd" then
                i = i + 1
                if not args[i] then print("Error: Option --luatexcmd requires a value."); usage(true) end
                options.luatexcmd = args[i]; options.luatexcmd_custom = true
            elseif opt == "margins" then
                i = i + 1
                if not args[i] then print("Error: Option --margins requires a value."); usage(true) end
                options.margins = args[i]
            elseif opt == "papersize" then
                i = i + 1
                if not args[i] then print("Error: Option --papersize requires a value."); usage(true) end
                options.papersize = args[i]
            elseif opt == "resolution" then
                i = i + 1
                if not args[i] then print("Error: Option --resolution requires a value."); usage(true) end
                options.resolution = args[i]
            elseif opt == "bbox" then
                i = i + 1
                if not args[i] then print("Error: Option --bbox requires a value."); usage(true) end
                options.bbox = args[i]
            elseif opt == "bbox-odd" then
                i = i + 1
                if not args[i] then print("Error: Option --bbox-odd requires a value."); usage(true) end
                options.bbox_odd = args[i]
            elseif opt == "bbox-even" then
                i = i + 1
                if not args[i] then print("Error: Option --bbox-even requires a value."); usage(true) end
                options.bbox_even = args[i]
            elseif opt == "pdfversion" then
                i = i + 1
                if not args[i] then print("Error: Option --pdfversion requires a value."); usage(true) end
                options.pdfversion = args[i]
            else
                print("Unknown option: " .. arg)
                usage(true)
            end
        elseif not end_of_options and arg == "-" then
            if not input_file then input_file = "-"
            elseif not output_file then output_file = "-" end
        else
            if not input_file then input_file = arg
            elseif not output_file then output_file = arg
            else
                print("Too many files!")
                usage(true)
            end
        end
        i = i + 1
    end
    return input_file, output_file
end

-- Main
local function main()
    local input_file, output_file = parse_args(arg)

    if options.version then
        print_version()
        return
    end

    if not input_file then
        usage(true)
    end

    if input_file ~= "-" then
        local f = io.open(input_file, "rb")
        if not f then
            print("Error: Input file not found: " .. input_file)
            cleanup(1)
        end
        f:close()
    end

    if not options.quiet then
        print(string.format("%s %s v%s - %s", PROGRAM, DATE, VERSION, COPYRIGHT))
        print(LUA_PORT_INFO)
    end

    if options.pdfversion and options.pdfversion ~= "auto" and options.pdfversion ~= "none" then
        local major, minor = options.pdfversion:match("^(%d)%.(%d)$")
        if not major then
            print("Error: Invalid --pdfversion format '" .. options.pdfversion .. "'")
            print("Expected format: X.Y where X and Y are single digits (e.g., 1.4, 1.7, 2.0)")
            cleanup(1)
        end
    end

    find_ghostscript()

    if not check_executable(options.gscmd) then
        print("Error: Ghostscript not found: " .. options.gscmd)
        print("Please install Ghostscript or specify a path with --gscmd")
        cleanup(1)
    end

    local margin_left, margin_top, margin_right, margin_bottom = 0, 0, 0, 0
    local m1, m2, m3, m4 = options.margins:match("^%s*([%-%d%.]+)%s+([%-%d%.]+)%s+([%-%d%.]+)%s+([%-%d%.]+)%s*$")
    if m1 then
        margin_left, margin_top, margin_right, margin_bottom = tonumber(m1), tonumber(m2), tonumber(m3), tonumber(m4)
    else
        m1, m2 = options.margins:match("^%s*([%-%d%.]+)%s+([%-%d%.]+)%s*$")
        if m1 then
            margin_left, margin_top, margin_right, margin_bottom = tonumber(m1), tonumber(m2), tonumber(m1), tonumber(m2)
        else
            m1 = options.margins:match("^%s*([%-%d%.]+)%s*$")
            if m1 then
                margin_left, margin_top, margin_right, margin_bottom = tonumber(m1), tonumber(m1), tonumber(m1), tonumber(m1)
            else
                print("Parse error (option --margins)!")
                cleanup(1)
            end
        end
    end

    local MAX_MARGIN = 10000  -- 10000bp is about 14 feet
    if math.abs(margin_left) > MAX_MARGIN or math.abs(margin_top) > MAX_MARGIN or
       math.abs(margin_right) > MAX_MARGIN or math.abs(margin_bottom) > MAX_MARGIN then
        print("Error: Margin values too large (max " .. MAX_MARGIN .. "bp)")
        cleanup(1)
    end

    debug_print("Margins: %g %g %g %g", margin_left, margin_top, margin_right, margin_bottom)
    debug_print("Input file: %s", input_file or "nil")
    debug_print("Output file: %s", output_file or "nil")
    debug_print("Ghostscript: %s", options.gscmd or "nil")

    local inputfilesafe
    if input_file == "-" then
        inputfilesafe = tmp_prefix .. "-stdin" .. EXT_PDF
        debug_print("Temporary input file: %s", inputfilesafe)
        local out, err = io.open(inputfilesafe, "wb")
        if not out then
            print("Error: Cannot write to " .. inputfilesafe .. " (" .. (err or "") .. ")")
            cleanup(1)
        end
        table.insert(unlink_files, inputfilesafe)
        local content = io.stdin:read("*a")
        if not content:match("^%%PDF%-") then
            print("Error: Standard input is not a valid PDF file!")
            cleanup(1)
        end
        out:write(content)
        out:close()
    elseif input_file:match(ffi.os == "Windows" and "[^%w%.%-%_/\\:]" or "[^%w%.%-%_/\\]") then
        inputfilesafe = tmp_prefix .. "-img" .. EXT_PDF
        debug_print("Copy input file to temporary file: %s", inputfilesafe)
        local inp = io.open(input_file, "rb")
        if not inp then
            print("Input file not found: " .. input_file)
            cleanup(1)
        end
        local out, err = io.open(inputfilesafe, "wb")
        if not out then
            print("Error: Cannot write to " .. inputfilesafe .. " (" .. (err or "") .. ")")
            cleanup(1)
        end
        table.insert(unlink_files, inputfilesafe)
        out:write(inp:read("*a"))
        inp:close()
        out:close()
    else
        inputfilesafe = input_file
    end


    if options.restricted then
        if options.gscmd_custom or options.pdftexcmd_custom or options.xetexcmd_custom or options.luatexcmd_custom then
            print("Error: Option restricted is set, custom commands are not allowed!")
            cleanup(1)
        end
        -- Use restricted versions of Ghostscript if available
        local restricted_cmd = "r" .. (options.gscmd or "gs")
        if check_executable(restricted_cmd) then
            options.gscmd = restricted_cmd
        else
            print("Warning: Restricted Ghostscript '" .. restricted_cmd .. "' not found")
        end
    end

    local tmp_tex = tmp_prefix .. EXT_TEX
    table.insert(unlink_files, tmp_tex)
    local tmp_f, err = io.open(tmp_tex, "w")
    if not tmp_f then
        print("Cannot open temporary file: " .. tmp_tex .. " (" .. (err or "") .. ")")
        cleanup(1)
    end

    -- Parse override bboxes
    local bbox_all, bbox_odd, bbox_even
    local function parse_bbox_opt(opt_str, opt_name)
        if not opt_str then return nil end
        local a, b, c, d = opt_str:match("^%s*([%-%d%.]+)%s+([%-%d%.]+)%s+([%-%d%.]+)%s+([%-%d%.]+)%s*$")
        if a then return {tonumber(a), tonumber(b), tonumber(c), tonumber(d)} end
        print("Error: Invalid " .. opt_name .. " format: '" .. opt_str .. "'")
        print("Expected format: 'left bottom right top' (e.g., '0 0 100 100')")
        tmp_f:close()
        cleanup(1)
    end

    bbox_all = parse_bbox_opt(options.bbox, "--bbox")
    bbox_odd = parse_bbox_opt(options.bbox_odd, "--bbox-odd")
    bbox_even = parse_bbox_opt(options.bbox_even, "--bbox-even")

    local MAX_BBOX_VALUE = 100000
    local function validate_bbox_value(v)
        return type(v) == "number" and v == v and v ~= math.huge and v ~= -math.huge and math.abs(v) < MAX_BBOX_VALUE
    end

    local function get_bbox(page, x1, y1, x2, y2)
        if page % 2 == 1 then
            if bbox_odd then return bbox_odd end
        else
            if bbox_even then return bbox_even end
        end
        if bbox_all then return bbox_all end
        return {x1, y1, x2, y2}
    end

    tmp_f:write([[\def\IfUndefined#1#2#3{%
    \expandafter\ifx\csname#1\endcsname\relax
    #2%
    \else
    #3%
    \fi
}
]])

    local pdffilehex = hex_encode(inputfilesafe)
tmp_f:write(string.format("\\def\\pdffilehex{%s}\n", pdffilehex))
tmp_f:write([[\IfUndefined{pdfunescapehex}{%
\begingroup
\gdef\pdffile{}%
\def\do#1#2{%
\ifx\relax#2\relax
\ifx\relax#1\relax
\else
\errmessage{Invalid hex string, should not happen!}%
\fi
\else
\lccode`0="#1#2\relax
\lowercase{%
\xdef\pdffile{\pdffile0}%
        }%
        \expandafter\do
        \fi
    }%
    \expandafter\do\pdffilehex\relax\relax
    \endgroup
}{%
\edef\pdffile{\pdfunescapehex{\pdffilehex}}%
}
\immediate\write-1{Input file: \pdffile}
]])

if options.tex == "luatex" then
    tmp_f:write([[\begingroup\expandafter\expandafter\expandafter\endgroup
    \expandafter\ifx\csname directlua\endcsname\relax
    \errmessage{LuaTeX not found!}%
    \fi
    ]])
end

local uncompress_val = options.uncompress and "0" or "9"
if options.tex == "pdftex" then
    tmp_f:write("\\pdfcompresslevel=" .. uncompress_val .. " ")
    tmp_f:write([[\pdfoutput=1 %
    \csname pdfmapfile\endcsname{}
    \def\setpdfversion#1#2{%
    \IfUndefined{pdfobjcompresslevel}{%
}{%
\ifnum#1=1 %
\ifnum#2<5
\pdfobjcompresslevel=0 %
\else
\pdfobjcompresslevel=2 %
\fi
\fi
  }%
  \IfUndefined{pdfminorversion}{%
  \IfUndefined{pdfoptionpdfminorversion}{%
    }{%
    \pdfoptionpdfminorversion=#2\relax
}%
  }{%
  \pdfminorversion=#2\relax
  \IfUndefined{pdfmajorversion}{%
  \ifnum#2=0 \pdfminorversion=5\fi}
  {\pdfmajorversion=#1\relax}%
  }%
}
\def\page #1 [#2 #3 #4 #5]{%
\count0=#1\relax
\setbox0=\hbox{%
\pdfximage page #1 mediabox{\pdffile}%
\pdfrefximage\pdflastximage
  }%
  \pdfhorigin=-#2bp\relax
  \pdfvorigin=#3bp\relax
  \pdfpagewidth=#4bp\relax
  \advance\pdfpagewidth by -#2bp\relax
  \pdfpageheight=#5bp\relax
  \advance\pdfpageheight by -#3bp\relax
  \ht0=\pdfpageheight
  \shipout\box0\relax
}
\def\pageclip #1 [#2 #3 #4 #5][#6 #7 #8 #9]{%
\count0=#1\relax
\dimen0=#4bp\relax \advance\dimen0 by -#2bp\relax
\edef\imagewidth{\the\dimen0}%
\dimen0=#5bp\relax \advance\dimen0 by -#3bp\relax
\edef\imageheight{\the\dimen0}%
\pdfximage page #1 mediabox{\pdffile}%
\setbox0=\hbox{%
\kern -#2bp\relax
\lower #3bp\hbox{\pdfrefximage\pdflastximage}%
  }%
  \wd0=\imagewidth\relax
  \ht0=\imageheight\relax
  \dp0=0pt\relax
  \pdfhorigin=#6pt\relax
  \pdfvorigin=#7bp\relax
  \pdfpagewidth=\imagewidth
  \advance\pdfpagewidth by #6bp\relax
  \advance\pdfpagewidth by #8bp\relax
  \pdfpageheight=\imageheight\relax
  \advance\pdfpageheight by #7bp\relax
  \advance\pdfpageheight by #9bp\relax
  \pdfxform0\relax
  \shipout\hbox{\pdfrefxform\pdflastxform}%
}%
\def\pageinclude#1{%
\pdfhorigin=0pt\relax
\pdfvorigin=0pt\relax
\pdfximage page #1 mediabox{\pdffile}%
\setbox0=\hbox{\pdfrefximage\pdflastximage}%
\pdfpagewidth=\wd0\relax
\pdfpageheight=\ht0\relax
\advance\pdfpageheight by \dp0\relax
\shipout\hbox{%
\raise\dp0\box0\relax
  }%
}
]])
if options.pdfversion and options.pdfversion ~= "auto" and options.pdfversion ~= "none" then
    local major, minor = options.pdfversion:match("^(%d)%.(%d)$")
    if major then
        tmp_f:write(string.format("\\setpdfversion{%s}{%s}\n", major, minor))
    end
end

    elseif options.tex == "luatex" then
        tmp_f:write("\\pdfvariable compresslevel=" .. uncompress_val .. " ")
        tmp_f:write([[\outputmode=1 %
        \pdfextension mapfile {}
        \def\setpdfversion#1#2{%
        \ifnum#1=1 %
        \ifnum#2<5
        \pdfvariable objcompresslevel=0 %
        \else
        \pdfvariable objcompresslevel=2 %
        \fi
        \fi
        \pdfvariable minorversion= #2
        \pdfvariable majorversion= #1
    }
    \def\page #1 [#2 #3 #4 #5]{%
    \count0=#1\relax
    \setbox0=\hbox{%
    \saveimageresource page #1 mediabox{\pdffile}%
    \useimageresource\lastsavedimageresourceindex
}%
\pdfvariable horigin=-#2bp\relax
\pdfvariable vorigin=#3bp\relax
\pagewidth=#4bp\relax
\advance\pagewidth by -#2bp\relax
\pageheight=#5bp\relax
\advance\pageheight by -#3bp\relax
\ht0=\pageheight
\shipout\box0\relax
}
\def\pageclip #1 [#2 #3 #4 #5][#6 #7 #8 #9]{%
\count0=#1\relax
\dimen0=#4bp\relax \advance\dimen0 by -#2bp\relax
\edef\imagewidth{\the\dimen0}%
\dimen0=#5bp\relax \advance\dimen0 by -#3bp\relax
\edef\imageheight{\the\dimen0}%
\saveimageresource page #1 mediabox{\pdffile}%
\setbox0=\hbox{%
\kern -#2bp\relax
\lower #3bp\hbox{\useimageresource\lastsavedimageresourceindex}%
  }%
  \wd0=\imagewidth\relax
  \ht0=\imageheight\relax
  \dp0=0pt\relax
  \pdfvariable horigin=#6pt\relax
  \pdfvariable vorigin=#7bp\relax
  \pagewidth=\imagewidth
  \advance\pagewidth by #6bp\relax
  \advance\pagewidth by #8bp\relax
  \pageheight=\imageheight\relax
  \advance\pageheight by #7bp\relax
  \advance\pageheight by #9bp\relax
  \saveboxresource0\relax
  \shipout\hbox{\useboxresource\lastsavedboxresourceindex}%
}%
\def\pageinclude#1{%
\pdfvariable horigin=0pt\relax
\pdfvariable vorigin=0pt\relax
\saveimageresource page #1 mediabox{\pdffile}%
\setbox0=\hbox{\useimageresource\lastsavedimageresourceindex}%
\pagewidth=\wd0\relax
\pageheight=\ht0\relax
\advance\pageheight by \dp0\relax
\shipout\hbox{%
\raise\dp0\box0\relax
  }%
}
]])
if options.pdfversion and options.pdfversion ~= "auto" and options.pdfversion ~= "none" then
    local major, minor = options.pdfversion:match("^(%d)%.(%d)$")
    if major then
        tmp_f:write(string.format("\\setpdfversion{%s}{%s}\n", major, minor))
    end
end

    else -- xetex
        tmp_f:write([[\expandafter\ifx\csname XeTeXpdffile\endcsname\relax
        \errmessage{XeTeX not found or too old!}%
        \fi
        \def\setpdfversion#1#2{%
        \special{pdf:majorversion #1}%
        \special{pdf:minorversion #2}}

        \def\page #1 [#2 #3 #4 #5]{%
        \count0=#1\relax
        \setbox0=\hbox{%
        \XeTeXpdffile "\pdffile" page #1 media\relax
    }%
    \pdfpagewidth=#4bp\relax
    \advance\pdfpagewidth by -#2bp\relax
    \pdfpageheight=#5bp\relax
    \advance\pdfpageheight by -#3bp\relax
    \shipout\hbox{%
    \kern-1in%
    \kern-#2bp%
    \vbox{%
    \kern-1in%
    \kern#3bp%
    \ht0=\pdfpageheight
    \box0 %
}%
  }%
}
\def\pageclip #1 [#2 #3 #4 #5][#6 #7 #8 #9]{%
\page {#1} [#2 #3 #4 #5]%
}
\def\pageinclude#1{%
\setbox0=\hbox{%
\XeTeXpdffile "\pdffile" page #1 media\relax
  }%
  \pdfpagewidth=\wd0\relax
  \pdfpageheight=\ht0\relax
  \advance\pdfpageheight by \dp0\relax
  \shipout\hbox{%
  \kern-1in%
  \vbox{%
  \kern-1in%
  \ht0=\pdfpageheight
  \box0 %
    }%
}%
}
]])
if options.pdfversion and options.pdfversion ~= "auto" and options.pdfversion ~= "none" then
    local major, minor = options.pdfversion:match("^(%d)%.(%d)$")
    if major then
        tmp_f:write(string.format("\\setpdfversion{%s}{%s}\n", major, minor))
    end
end

    end

    if options.verbose then print("* Running Ghostscript for BoundingBox calculation ...") end
    local gs_out_file = tmp_prefix .. EXT_GSOUT
    table.insert(unlink_files, gs_out_file)

    local gsargs = {
        "-sDEVICE=bbox",
        "-dBATCH",
        "-dNOPAUSE"
    }
    if options.papersize then
        if not options.papersize:match("^[%w_]+$") then
            print("Error: Invalid papersize: " .. options.papersize)
            cleanup(1)
        end
        local valid_sizes = {
            letter=true, legal=true, a0=true, a1=true, a2=true, a3=true, a4=true, a5=true, a6=true,
            b0=true, b1=true, b2=true, b3=true, b4=true, b5=true, b6=true,
            ledger=true, tabloid=true, statement=true, executive=true, folio=true, quarto=true, ["10x14"]=true
        }
        if not valid_sizes[options.papersize:lower()] then
            print("Warning: Unknown papersize '" .. options.papersize .. "', using it anyway.")
        end
        table.insert(gsargs, "-sPAPERSIZE=" .. options.papersize)
    end
    if options.resolution then
        local res_num = tonumber(options.resolution)
        if not res_num or res_num < 1 or res_num > 9999 then
            print("Error: Invalid resolution: " .. options.resolution .. " (must be 1-9999)")
            cleanup(1)
        end
        table.insert(gsargs, "-r" .. options.resolution)
    end
    table.insert(gsargs, "-c")
    table.insert(gsargs, "save")
    table.insert(gsargs, "pop")
    table.insert(gsargs, "-f")
    table.insert(gsargs, inputfilesafe) -- Don't quote here, we quote in loop

    local gs_cmd_str = shell_quote(options.gscmd)

    for _, a in ipairs(gsargs) do
        gs_cmd_str = gs_cmd_str .. " " .. shell_quote(a)
    end

    gs_cmd_str = gs_cmd_str .. " > " .. shell_quote(gs_out_file) .. " 2>&1"
    debug_print("Ghostscript call: %s", gs_cmd_str)

    local gs_ret, gs_kind, gs_code = execute_command(gs_cmd_str)

    local page = 0
    local bb_token = options.hires and "%%HiResBoundingBox" or "%%BoundingBox"

    local gs_out_f, open_err = io.open(gs_out_file, "r")
    if not gs_out_f then
        print("Error: Cannot read Ghostscript output file: " .. gs_out_file .. " (" .. (open_err or "") .. ")")
        tmp_f:close()
        cleanup(1)
    end

    local first_byte = gs_out_f:read(1)
    if not first_byte then
        print("Error: Ghostscript produced no output (file may be corrupt or GS crashed)")
        gs_out_f:close()
        tmp_f:close()
        cleanup(1)
    end
    gs_out_f:seek("set", 0)

    for line in gs_out_f:lines() do
        if options.verbose then print(line) end
        local x1, y1, x2, y2 = line:match(bb_token .. ":%s*([%-%d%.]+)%s+([%-%d%.]+)%s+([%-%d%.]+)%s+([%-%d%.]+)")
        if x1 then
            page = page + 1
            local box_gs = {tonumber(x1), tonumber(y1), tonumber(x2), tonumber(y2)}
            if not (validate_bbox_value(box_gs[1]) and validate_bbox_value(box_gs[2]) and validate_bbox_value(box_gs[3]) and validate_bbox_value(box_gs[4])) then
                print(string.format("!!! Error: Invalid BoundingBox values returned by Ghostscript for page %d!", page))
                gs_out_f:close()
                tmp_f:close()
                cleanup(1)
            end
            local box = get_bbox(page, box_gs[1], box_gs[2], box_gs[3], box_gs[4])

            if box[1] >= box[3] or box[2] >= box[4] then
                print(string.format("\n!!! Warning: Empty Bounding Box detected!\n!!!   Page %d: GS reported [%s %s %s %s], effective [%s %s %s %s]\n!!! Recovery is tried by embedding the page in its original size.\n",
                    page, box_gs[1], box_gs[2], box_gs[3], box_gs[4], box[1], box[2], box[3], box[4]))
                tmp_f:write(string.format("\\pageinclude{%d}\n", page))
            else
                if options.verbose then print(string.format("* Page %d: %g %g %g %g", page, box[1], box[2], box[3], box[4])) end

                local bb = {box[1] - margin_left, box[2] - margin_bottom, box[3] + margin_right, box[4] + margin_top}
                if bb[1] >= bb[3] or bb[2] >= bb[4] then
                    print(string.format("\n!!! Warning: The final Bounding Box is empty!\n!!!   Page: %d: %g %g %g %g\n!!! Probably caused by too large negative margin values.\n!!! Recovery by ignoring margin values.\n", page, bb[1], bb[2], bb[3], bb[4]))
                    tmp_f:write(string.format("\\page %d [%g %g %g %g]\n", page, box[1], box[2], box[3], box[4]))
                else
                    if options.clip then
                        tmp_f:write(string.format("\\pageclip %d [%g %g %g %g][%g %g %g %g]\n", page, box[1], box[2], box[3], box[4], margin_left, margin_top, margin_right, margin_bottom))
                    else
                        tmp_f:write(string.format("\\page %d [%g %g %g %g]\n", page, bb[1], bb[2], bb[3], bb[4]))
                    end
                end
            end
        end
    end
    gs_out_f:close()

    local success, exit_code = exec_success(gs_ret, gs_kind, gs_code)
    if not success then
        print(string.format("Ghostscript execution failed (exit code %d)!", exit_code))
        tmp_f:close()
        cleanup(1)
    end

    if page == 0 then
        print("Ghostscript does not report bounding boxes!")
        tmp_f:close()
        cleanup(1)
    end

    tmp_f:write("\\csname @@end\\endcsname\n\\end\n")
    local close_ok, close_err = tmp_f:close()
    if not close_ok then
        print("Error: Failed to close temporary TeX file: " .. (close_err or "unknown error"))
        cleanup(1)
    end

    -- Run TeX
    local tex_cmd
    local tex_name
    if options.tex == "pdftex" then
        tex_cmd = options.pdftexcmd
        tex_name = "pdfTeX"
    elseif options.tex == "luatex" then
        tex_cmd = options.luatexcmd
        tex_name = "LuaTeX"
    else
        tex_cmd = options.xetexcmd
        tex_name = "XeTeX"
    end

    if not check_executable(tex_cmd) then
        print("Error: " .. tex_name .. " command not found: " .. tex_cmd)
        print("Please install " .. tex_name .. " or specify a different engine with --pdftex/--xetex/--luatex")
        cleanup(1)
    end

    local full_tex_cmd = shell_quote(tex_cmd) .. " -no-shell-escape"
    if options.initex then
        full_tex_cmd = full_tex_cmd .. " --ini --etex"
    end
    if options.verbose then
        full_tex_cmd = full_tex_cmd .. " -interaction=nonstopmode " .. shell_quote(tmp_tex)
    else
        full_tex_cmd = full_tex_cmd .. " -interaction=batchmode " .. shell_quote(tmp_tex)
    end
    if options.verbose then print("* Running " .. tex_name .. " ...") end
    debug_print("%s call: %s", tex_name, full_tex_cmd)

    table.insert(unlink_files, tmp_prefix .. EXT_LOG)
    local tex_res, tex_kind, tex_code = execute_command(full_tex_cmd)
    local success, exit_code = exec_success(tex_res, tex_kind, tex_code)
    if not success then
        print(tex_name .. string.format(" run failed (exit code %d)!", exit_code))
        cleanup(1)
    end

    local tmp_pdf = tmp_prefix .. EXT_PDF
    table.insert(unlink_files, tmp_pdf)

    if options.pdfversion and options.pdfversion ~= "auto" and options.pdfversion ~= "none" then
        local pdf_f = io.open(tmp_pdf, "rb")
        if not pdf_f then
            print("!!! Error: Cannot open `" .. tmp_pdf .. "`!")
            cleanup(1)
        end
        local header = pdf_f:read(9)
        pdf_f:close()

        local ver = header:match("%%PDF%-(%d%.%d)")
        if ver and ver ~= options.pdfversion then
            debug_print("PDF version correction in output file: %s", options.pdfversion)
            local pdf_f_rw = io.open(tmp_pdf, "r+b")
            if pdf_f_rw then
                local new_header = "%PDF-" .. options.pdfversion
                pdf_f_rw:seek("set", 0)
                pdf_f_rw:write(new_header)
                pdf_f_rw:close()
            end
        end
    end

    if not output_file then
        if input_file == "-" then
            output_file = "stdin-crop" .. EXT_PDF
        else
            output_file = input_file:gsub(PDF_EXT_PATTERN, "") .. "-crop" .. EXT_PDF
        end
    end
    if output_file == input_file then
        output_file = input_file .. "-crop" .. EXT_PDF
    end

    -- Rename/Move
    os.remove(output_file)
    local ok, err = os.rename(tmp_pdf, output_file)
    if not ok then
        -- Fallback to copy if rename fails (e.g. across partitions)
        local f_in = io.open(tmp_pdf, "rb")
        if not f_in then
            print("Error: Cannot read temporary file: " .. tmp_pdf)
            cleanup(1)
        end
        local f_out, err_open = io.open(output_file, "wb")
        if not f_out then
            f_in:close()
            print("Error: Cannot write to output file: " .. output_file .. " (" .. (err_open or "") .. ")")
            cleanup(1)
        end
        local write_ok, write_err = f_out:write(f_in:read("*a"))
        f_in:close()
        f_out:close()
        if not write_ok then
            os.remove(output_file)
            print("Error: Failed to write output file: " .. (write_err or "unknown error"))
            cleanup(1)
        end
        os.remove(tmp_pdf)
    end

    if not options.quiet then
        print(string.format("==> %d page%s written on `%s'.", page, page == 1 and "" or "s", output_file))
    end

    cleanup(0)
end

main()
