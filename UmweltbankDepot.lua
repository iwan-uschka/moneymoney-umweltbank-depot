-- MoneyMoney Extension: Umweltbank Depot
--
-- Umweltbank's login POST encrypts credentials with JWE (JSON Web Encryption,
-- RSA-OAEP-512 + AES-GCM). Implementing RSA-OAEP in Lua is not feasible, so the
-- QR-code login path is used instead. The server issues a short-lived JWT; the
-- user scans it with SecureGo plus (which holds the private key on their phone);
-- the server sees the phone's approval and grants the session without any
-- credential encryption on the extension's side.
--
-- Prerequisite: QR login must be activated once via the browser at
-- banking.umweltbank.de before this extension can be used.

local BASE = "https://banking.umweltbank.de"

-- ── QR auth endpoints (Atruvia/CAS layer) ───────────────────────────────────
-- QR_INIT_UI_ENDPOINT   : starts the CAS session and returns the bank branding config.
--                         Side-effect: sets the CAS_SESSION cookie needed by all later calls.
-- QR_INIT_CODE_ENDPOINT : issues a signed JWT that encodes the login challenge.
--                         The JWT is what gets encoded into the QR image.
-- QR_STATUS_ENDPOINT    : polled to detect when the user has scanned the code.
-- QR_LOGIN_ENDPOINT     : tells the backend "this JWT was approved" and advances the auth flow.
local QR_INIT_UI_ENDPOINT   = BASE .. "/services_auth/auth-qr-service/api/init-ui?theme=LIGHT&locale=de-DE"
local QR_INIT_CODE_ENDPOINT = BASE .. "/services_auth/auth-qr-service/api/init-qr-code"
local QR_STATUS_ENDPOINT    = BASE .. "/services_auth/auth-qr-service/api/status"
local QR_LOGIN_ENDPOINT     = BASE .. "/services_auth/auth-backend/api/authentication/qr-login"

-- ── CAS session initiation ───────────────────────────────────────────────────
-- GET CAS_AUTHORIZE_ENDPOINT issues a 302 that sets the CAS_SESSION cookie.
-- auth-qr-service rejects all requests without it ("Cookie 'CAS_SESSION' not found").
-- client_id and claims are fixed values the portal always sends; state/nonce are random.
local CAS_AUTHORIZE_ENDPOINT = BASE .. "/services_auth/oauth2/authorize"
local CAS_REDIRECT_URI       = BASE .. "/services_cloud/portal/portal-oauth/login"
local CAS_CLAIMS             = "%7B%22id_token%22:%7B%22https://cas.bankenit.de/id/type%22:%7B%22essential%22:true%7D,%22https://cas.bankenit.de/id/tan_status%22:%7B%22essential%22:false%7D,%22birthdate%22:%7B%22essential%22:true%7D,%22https://cas.bankenit.de/id/salutation%22:%7B%22essential%22:true%7D,%22https://cas.bankenit.de/id/version%22:%7B%22essential%22:true%7D,%22https://cas.bankenit.de/id/allowed_scopes%22:%7B%22essential%22:true%7D,%22given_name%22:%7B%22essential%22:true%7D,%22https://cas.bankenit.de/id/bankKunde%22:%7B%22essential%22:true%7D,%22acr%22:%7B%22essential%22:true,%22values%22:%5B%22onlinebanking_psd2%22,%22onlinebanking_pin%22%5D%7D,%22https://cas.bankenit.de/id/pin_status%22:%7B%22essential%22:false%7D,%22https://cas.bankenit.de/id/last_login%22:%7B%22essential%22:true%7D,%22family_name%22:%7B%22essential%22:true%7D,%22email%22:%7B%22essential%22:true%7D,%22jti%22:%7B%22essential%22:true%7D,%22https://cas.bankenit.de/id/vertriebskunden_id%22:%7B%22essential%22:true%7D,%22sid%22:%7B%22essential%22:true%7D%7D%7D"

-- ── Portal OAuth endpoints ───────────────────────────────────────────────────
-- CONSENT_ENDPOINT  : completes the CAS login and returns the CAS callback parameters
--                     (code, state, iss) that portal-oauth/login must receive.
-- AUTHORIZE_ENDPOINT: the portal's own OAuth 2.0 authorization endpoint.  Always
--                     responds with a 302 redirect to REDIRECT_URI?code=<portal_code>.
--                     MoneyMoney follows all redirects automatically, so the portal
--                     code is only ever visible in the MoneyMoney log — not from Lua.
-- TOKEN_ENDPOINT    : exchanges the portal code for access_token/refresh_token.
--                     Tokens may be returned as HttpOnly cookies (sent automatically
--                     by MoneyMoney's cookie jar) or as JSON (stored in g_access_token).
-- REDIRECT_URI      : where the portal expects the auth code to land. Must match
--                     exactly what the portal registered.
local CONSENT_ENDPOINT   = BASE .. "/services_auth/auth-backend/api/consent/execution"
local AUTHORIZE_ENDPOINT = BASE .. "/services_cloud/portal/portal-oauth/oauth/authorize"
local TOKEN_ENDPOINT     = BASE .. "/services_cloud/portal/portal-oauth/oauth/token"
local REDIRECT_URI       = BASE .. "/services_cloud/portal/login"

-- ── Data endpoints ───────────────────────────────────────────────────────────
-- KONTO_GROUP_ENDPOINT : lists all accounts grouped by type; filtered for art == "DEPOT".
-- DEPOTS_ENDPOINT      : GET depots/{depotNummer} — returns positions with last-trading-day
--                        prices (kursAktuell). depotwert is always 0; sum kurswertEUR instead.
local KONTO_GROUP_ENDPOINT = BASE .. "/services_cloud/portal/proxy-gateway/serviceproxy/konto-service/v2/konto/group"
local _BESTAND_BASE   = BASE .. "/services_cloud/portal/proxy-gateway/serviceproxy/wporder-bestand-service-v1/rest/de.fiduciagad.dzwp.wporder.bestand.v1.bestand.BestandApi"
local DEPOTS_ENDPOINT = _BESTAND_BASE .. "/depots/"   -- append depotNummer at runtime

-- ─────────────────────────────────────────────────────────────────────────────
-- GF(256) – Galois Field arithmetic
-- ─────────────────────────────────────────────────────────────────────────────

local GF_EXP, GF_LOG = {}, {}
do
  local x = 1
  for i = 0, 254 do
    GF_EXP[i] = x
    GF_LOG[x] = i
    x = x * 2
    -- Multiplying by 2 in GF(256): shift left 1 bit.
    -- If the result exceeds 255 (i.e. the x^8 bit is set), XOR with 0x11D
    -- to reduce back into the field (equivalent to subtracting the polynomial).
    if x > 255 then x = (x ~ 0x11D) & 0xFF end
  end
  for i = 255, 511 do GF_EXP[i] = GF_EXP[i - 255] end
end

local function gf_mul(a, b)
  if a == 0 or b == 0 then return 0 end
  -- log(a) + log(b) mod 255 gives the exponent of the product.
  return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Reed-Solomon error correction encoder (EC Level L, ~7% recovery)
-- ─────────────────────────────────────────────────────────────────────────────

local function rs_generator(n)
  local g = {1}  -- start with the polynomial "1"
  for i = 0, n - 1 do
    -- Multiply g by (x - α^i) = (x + α^i) in GF(256) (subtraction = XOR = addition)
    local ng = {}
    for j = 1, #g + 1 do ng[j] = 0 end
    for j = 1, #g do
      ng[j]   = ng[j]   ~ g[j]
      ng[j+1] = ng[j+1] ~ gf_mul(g[j], GF_EXP[i])
    end
    g = ng
  end
  return g
end

local function rs_encode(data, n_ec)
  local gen = rs_generator(n_ec)
  -- Append n_ec zero bytes as placeholders for the remainder
  local msg = {}
  for _, v in ipairs(data) do msg[#msg+1] = v end
  for _ = 1, n_ec do msg[#msg+1] = 0 end
  -- Polynomial long division: for each data byte, eliminate the leading term
  -- by XOR-adding the generator scaled by that byte.
  for i = 1, #data do
    local c = msg[i]
    if c ~= 0 then
      for j = 1, #gen do
        msg[i+j-1] = msg[i+j-1] ~ gf_mul(gen[j], c)
      end
    end
  end
  -- The first #data positions are now zero (consumed); the remainder is the EC bytes.
  local ec = {}
  for i = #data + 1, #msg do ec[#ec+1] = msg[i] end
  return ec
end

-- ─────────────────────────────────────────────────────────────────────────────
-- QR capacity tables, EC Level L: {ec_cw_per_block, g1_count, g1_data_cw, g2_count, g2_data_cw}
-- ─────────────────────────────────────────────────────────────────────────────

local EC_L = {
  [1]  = { 7, 1, 19, 0,  0},  [2]  = {10, 1, 34, 0,  0},
  [3]  = {15, 1, 55, 0,  0},  [4]  = {20, 1, 80, 0,  0},
  [5]  = {26, 1,108, 0,  0},  [6]  = {18, 2, 68, 0,  0},
  [7]  = {20, 2, 78, 0,  0},  [8]  = {24, 2, 97, 0,  0},
  [9]  = {30, 2,116, 0,  0},  [10] = {18, 2, 68, 2, 69},
  [11] = {20, 4, 81, 0,  0},  [12] = {24, 2, 92, 2, 93},
  [13] = {26, 4,107, 0,  0},  [14] = {30, 3,115, 1,116},
  [15] = {22, 5, 87, 1, 88},  [16] = {24, 5, 98, 1, 99},
  [17] = {28, 1,107, 5,108},  [18] = {30, 5,120, 1,121},
  [19] = {28, 3,113, 4,114},  [20] = {28, 3,107, 5,108},
  [21] = {28, 4,116, 4,117},  [22] = {28, 2,111, 7,112},
  [23] = {30, 4,121, 5,122},  [24] = {30, 6,117, 4,118},
  [25] = {26, 8,106, 4,107},
}

-- Maximum USER data bytes encodable per version at EC Level L.
-- Smaller than the total codeword count because a portion is reserved for RS
-- check bytes.  A 840-byte JWT typically requires version 20 (capacity 858).
local CAP_L = {
   17, 32, 53, 78,106,134,154,192,230,271,
  321,367,425,458,520,586,644,718,792,858,
  929,1003,1091,1171,1273
}

-- Centre coordinates of alignment patterns per version.
-- Alignment patterns are 5×5 "bull's-eye" squares placed at every pairwise
-- intersection of the listed coordinates.  They help QR scanners correct
-- perspective distortion and lens curvature in larger symbols.
-- Version 1 has no alignment patterns; they only appear from version 2 up.
-- Intersections that would overlap a finder pattern or the timing strip are
-- skipped automatically during placement (see place_alignment).
local ALIGN = {
  [2]={6,18},             [3]={6,22},             [4]={6,26},
  [5]={6,30},             [6]={6,34},             [7]={6,22,38},
  [8]={6,24,42},          [9]={6,26,46},          [10]={6,28,50},
  [11]={6,30,54},         [12]={6,32,58},         [13]={6,34,62},
  [14]={6,26,46,66},      [15]={6,26,48,70},      [16]={6,26,50,74},
  [17]={6,30,54,78},      [18]={6,30,56,82},      [19]={6,30,58,86},
  [20]={6,34,62,90},      [21]={6,28,50,72,94},   [22]={6,26,50,74,98},
  [23]={6,30,54,78,102},  [24]={6,28,54,80,106},  [25]={6,32,58,84,110},
}

-- ─────────────────────────────────────────────────────────────────────────────
-- Matrix helpers
-- ─────────────────────────────────────────────────────────────────────────────

-- 0-indexed 2-D table of nils. nil = module not yet assigned (data can go here).
local function new_mat(n)
  local m = {}
  for r = 0, n-1 do m[r] = {} end
  return m
end

-- Returns true when (r,c) is a FUNCTION module that must never be data-masked.
-- Masking is only applied to data modules; function modules have fixed values
-- defined by the spec and must survive unchanged regardless of which mask is used.
local function is_func(ver, n, r, c)
  -- Each of the three finder patterns occupies a 7×7 square, surrounded by a
  -- 1-module white separator, with format-info modules beyond that – giving a
  -- 9×9 reserved corner.  There is no finder in the bottom-right corner, which
  -- lets scanners determine symbol orientation.
  if r <= 8 and c <= 8 then return true end    -- top-left
  if r <= 8 and c >= n-8 then return true end  -- top-right
  if r >= n-8 and c <= 8 then return true end  -- bottom-left

  -- Timing patterns: alternating dark/light row 6 and column 6 between finders.
  -- They let the decoder calculate the exact module grid even in blurry images.
  if r == 6 or c == 6 then return true end

  -- Alignment patterns: 5×5 squares at pairwise intersections of ALIGN coords,
  -- excluding the three corners that overlap finder patterns.
  local ap = ALIGN[ver]
  if ap then
    local ap1, apl = ap[1], ap[#ap]
    for _, cr in ipairs(ap) do
      for _, cc in ipairs(ap) do
        local finder_corner = (cr == ap1 and (cc == ap1 or cc == apl)) or (cr == apl and cc == ap1)
        if not finder_corner and math.abs(r-cr) <= 2 and math.abs(c-cc) <= 2 then return true end
      end
    end
  end

  -- Version information block (QR code version 7 and above): two 6×3 rectangles encoding the version number.
  if ver >= 7 then
    if r >= n-11 and r <= n-9 and c <= 5 then return true end
    if c >= n-11 and c <= n-9 and r <= 5 then return true end
  end

  return false
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Function-pattern placement
-- ─────────────────────────────────────────────────────────────────────────────

-- Finder pattern: a 7×7 "bull's-eye" (dark border, light ring, dark 3×3 centre)
-- surrounded by a 1-module white separator.  Three are placed in the corners;
-- the missing fourth corner uniquely identifies the symbol's orientation.
-- The distinctive concentric-square pattern is detectable at any scale and angle.
local function place_finder(m, n, r0, c0)
  for dr = -1, 7 do
    for dc = -1, 7 do
      local val
      if dr == -1 or dr == 7 or dc == -1 or dc == 7 then
        val = 0  -- white separator border
      elseif dr == 0 or dr == 6 or dc == 0 or dc == 6 then
        val = 1  -- dark outer ring of the 7×7 square
      elseif dr >= 2 and dr <= 4 and dc >= 2 and dc <= 4 then
        val = 1  -- dark 3×3 centre square
      else
        val = 0  -- light ring between outer and centre
      end
      local r, c = r0+dr, c0+dc
      -- Guard against the top-left finder's separator going to row -1
      if m[r] and c >= 0 and c < n then m[r][c] = val end
    end
  end
end

-- Alignment pattern: a 5×5 square (dark border, light ring, single dark centre).
-- The nil-check prevents overwriting timing-pattern or finder-pattern modules
-- that happen to lie within the 5×5 area of a theoretically-placed pattern.
local function place_alignment(m, cr, cc)
  for dr = -2, 2 do
    for dc = -2, 2 do
      local val = (dr==-2 or dr==2 or dc==-2 or dc==2 or (dr==0 and dc==0)) and 1 or 0
      if m[cr+dr] and m[cr+dr][cc+dc] == nil then
        m[cr+dr][cc+dc] = val
      end
    end
  end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Format information and version information
-- ─────────────────────────────────────────────────────────────────────────────

-- EC Level L is represented as binary "01" (= 1) in the format info bits.
local EC_L_IND = 1

-- Encodes the 5-bit format data (EC indicator + 3-bit mask number) into a 15-bit
-- codeword using a BCH(15,5) error-correcting code with generator 0x537.
--
-- The BCH code means a QR decoder can recover the format info even if up to 3
-- of the 15 modules are destroyed.
--
-- The final XOR with 0x5412 is a fixed mask that ensures the 15-bit string is
-- never all-zeros (which would be indistinguishable from a blank row/column).
local function format_info_word(mask)
  local data = EC_L_IND * 8 + mask  -- 5-bit input: [ec1 ec0 m2 m1 m0]
  local d = data << 10
  local g = 0x537  -- BCH generator: x^10+x^8+x^5+x^4+x^2+x+1
  for i = 14, 10, -1 do
    if (d >> i) & 1 == 1 then d = d ~ (g << (i-10)) end
  end
  return ((data << 10) | (d & 0x3FF)) ~ 0x5412
end

-- Encodes the version number (7-25) into an 18-bit word using a BCH(18,6) code
-- with generator 0x1F25.  Only needed for QR code version 7 and above; smaller symbols
-- do not carry version information modules (the reader infers the version from
-- the symbol size).
local function version_info_word(ver)
  local d = ver << 12
  local g = 0x1F25  -- BCH generator: x^12+x^11+x^10+x^9+x^8+x^5+x^2+1
  for i = 17, 12, -1 do
    if (d >> i) & 1 == 1 then d = d ~ (g << (i-12)) end
  end
  return (ver << 12) | (d & 0xFFF)
end

-- Writes the 15-bit format info word into two copies: L-strip at top-left, mirrored at top-right and bottom-left.
-- Spec (ISO 18004 Fig. 25): bit14 (MSB) at (8,0), bit13 at (8,1), ..., bit9 at (8,5),
-- bit8 at (8,7) [col 6 = timing skipped], bit7 at (8,8),
-- bit6..bit0 at rows (7,8),(5,8)..(0,8) [row 6 = timing skipped].
-- Copy 2: bit0..bit7 at (8,n-1)..(8,n-8); bit8..bit14 at (n-7,8)..(n-1,8).
local function place_format(m, n, fi)
  local bits = {}
  for b = 14, 0, -1 do bits[#bits+1] = (fi >> b) & 1 end
  -- bits[1]=bit14 (MSB) … bits[15]=bit0 (LSB)

  -- Copy 1: bit14 at (8,0), down to bit0 at (0,8)
  local bi = 1  -- start at MSB (bit14)
  for c = 0, 5 do m[8][c] = bits[bi]; bi=bi+1 end   -- bits 14..9 at cols 0..5
  m[8][7] = bits[bi]; bi=bi+1                         -- bit 8 at col 7 (col 6 = timing)
  m[8][8] = bits[bi]; bi=bi+1                         -- bit 7 at col 8

  for r = 7, 0, -1 do
    if r ~= 6 then m[r][8] = bits[bi]; bi=bi+1 end   -- bits 6..0 at rows 7,5,4,3,2,1,0
  end

  -- Copy 2 top-right: bit0..bit7 at row 8, cols n-1..n-8 (8 modules)
  bi = 15  -- start at bit0 (LSB)
  for c = n-1, n-8, -1 do m[8][c] = bits[bi]; bi=bi-1 end

  -- Copy 2 bottom-left: bit8..bit14 at col 8, rows n-7..n-1 (7 modules; bi continues from 7)
  for r = n-7, n-1 do m[r][8] = bits[bi]; bi=bi-1 end
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Data encoding – byte mode, EC Level L
-- ─────────────────────────────────────────────────────────────────────────────

local function encode_data(text, ver)
  local t = EC_L[ver]
  local ec_pw, g1n, g1d, g2n, g2d = t[1], t[2], t[3], t[4], t[5]
  local total_data = g1n*g1d + g2n*g2d  -- total data codewords across all blocks

  -- ── Build the raw bit stream ─────────────────────────────────────────────
  local bits = {}
  local function push(v, nb)
    for b = nb-1, 0, -1 do bits[#bits+1] = (v>>b)&1 end
  end

  -- Mode indicator: 0100 = byte mode (encodes arbitrary bytes, simplest for JWT)
  push(4, 4)
  -- Character count: 8 bits for versions 1-9, 16 bits for versions 10+
  push(#text, ver < 10 and 8 or 16)
  -- Payload bytes
  for i = 1, #text do push(string.byte(text,i), 8) end

  -- Terminator: up to 4 zero bits to signal end of data
  local avail = total_data*8 - #bits
  for _ = 1, math.min(4, avail) do bits[#bits+1] = 0 end
  -- Pad to the next byte boundary
  while #bits % 8 ~= 0 do bits[#bits+1] = 0 end
  -- Fill remaining capacity with alternating pad bytes 0xEC / 0x11
  -- (spec-defined; they look like random data to avoid accidental patterns)
  local pad = {0xEC, 0x11}; local pi = 1
  while #bits < total_data*8 do
    push(pad[pi], 8); pi = (pi%2)+1
  end

  -- ── Convert bit stream to codewords (bytes) ──────────────────────────────
  local cw = {}
  for i = 1, #bits, 8 do
    local b = 0
    for j = 0, 7 do b = b*2 + (bits[i+j] or 0) end
    cw[#cw+1] = b
  end

  -- ── Split codewords into blocks ──────────────────────────────────────────
  -- Each block is RS-encoded independently.  Using multiple blocks means that
  -- a contiguous burst of damage only destroys a few bytes in each block, which
  -- RS can correct, rather than concentrating the damage in one unrecoverable block.
  local blocks = {}; local pos = 1
  for _ = 1, g1n do
    local blk = {}
    for j = 1, g1d do blk[j] = cw[pos]; pos=pos+1 end
    blocks[#blocks+1] = blk
  end
  for _ = 1, g2n do  -- group 2 blocks carry one extra data codeword each
    local blk = {}
    for j = 1, g2d do blk[j] = cw[pos]; pos=pos+1 end
    blocks[#blocks+1] = blk
  end

  -- ── Reed-Solomon error correction per block ──────────────────────────────
  local ec_blocks = {}
  for _, blk in ipairs(blocks) do
    ec_blocks[#ec_blocks+1] = rs_encode(blk, ec_pw)
  end

  -- ── Interleave data codewords, then EC codewords ─────────────────────────
  -- Interleaving spreads each block's bytes across the whole symbol.  If one
  -- region of the printed QR code is damaged, each block only loses a few
  -- scattered bytes rather than a long contiguous run – well within RS capacity.
  local final = {}
  local max_d = g2n > 0 and g2d or g1d
  for i = 1, max_d do
    for _, blk in ipairs(blocks) do
      if blk[i] then final[#final+1] = blk[i] end  -- group 1 blocks are 1 shorter
    end
  end
  for i = 1, ec_pw do
    for _, ec in ipairs(ec_blocks) do
      if ec[i] then final[#final+1] = ec[i] end
    end
  end
  return final
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Matrix construction
-- ─────────────────────────────────────────────────────────────────────────────

local function build_matrix(ver, codewords)
  -- Version N produces an (4N+17) × (4N+17) module grid.
  -- Version 1 = 21×21 (the smallest), version 40 = 177×177 (the largest).
  local n = 4*ver + 17
  local m = new_mat(n)  -- nil = unassigned (available for data)

  -- ── Finder patterns (three corners) ─────────────────────────────────────
  place_finder(m, n, 0,   0)    -- top-left
  place_finder(m, n, 0,   n-7)  -- top-right
  place_finder(m, n, n-7, 0)    -- bottom-left
  -- (no bottom-right finder – the empty corner identifies symbol orientation)

  -- ── Timing patterns ──────────────────────────────────────────────────────
  -- Alternating dark/light modules along row 6 and column 6 between the finders.
  -- A scanner counts these modules to determine the exact grid cell size.
  for i = 8, n-9 do
    m[6][i] = (i%2==0) and 1 or 0
    m[i][6] = (i%2==0) and 1 or 0
  end

  -- ── Dark module ───────────────────────────────────────────────────────────
  -- Always dark; placed at a fixed position defined by the spec.
  -- Its purpose is largely historical – it prevents all-zero format info in
  -- very small masks and helps some early decoders recognise valid symbols.
  m[4*ver+9][8] = 1

  -- ── Alignment patterns ───────────────────────────────────────────────────
  local ap = ALIGN[ver]
  if ap then
    local ap1, apl = ap[1], ap[#ap]
    for _, cr in ipairs(ap) do
      for _, cc in ipairs(ap) do
        local finder_corner = (cr == ap1 and (cc == ap1 or cc == apl)) or (cr == apl and cc == ap1)
        if not finder_corner then
          place_alignment(m, cr, cc)
        end
      end
    end
  end

  -- ── Reserve format-info and version-info areas ───────────────────────────
  -- Fill with 0 so that the zigzag data-placement loop (below) skips these spots.
  -- The real format info bits are written AFTER masking is complete (place_format),
  -- because the format word encodes which mask was chosen.
  for i = 0, 8 do  -- top-left: row 8 cols 0-8, col 8 rows 0-8 (all is_func)
    if m[8][i] == nil then m[8][i] = 0 end
    if m[i][8] == nil then m[i][8] = 0 end
  end
  for i = 0, 7 do  -- top-right / bottom-left: only n-1..n-8 (all is_func); n-9 is a data cell
    if m[8][n-1-i]   == nil then m[8][n-1-i]   = 0 end
    if m[n-1-i][8]   == nil then m[n-1-i][8]   = 0 end
  end
  if ver >= 7 then  -- version info blocks only from QR code version 7 onwards
    for i = 0, 2 do for j = 0, 5 do
      m[n-11+i][j] = 0; m[j][n-11+i] = 0
    end end
  end

  -- ── Expand codewords into a flat bit array ───────────────────────────────
  local bits = {}
  for _, cw in ipairs(codewords) do
    for b = 7, 0, -1 do bits[#bits+1] = (cw>>b)&1 end
  end

  -- ── Place data bits in a two-column zigzag, right to left ────────────────
  -- The QR spec places data in pairs of adjacent columns, sweeping from the
  -- right edge inward.  Within each column-pair the direction alternates:
  -- first pair goes bottom-to-top, next goes top-to-bottom, etc.
  -- Any module that is already set (function pattern) is skipped.
  local bi = 1
  local going_up = true
  local col = n-1
  while col >= 1 do
    if col == 6 then col = col-1 end  -- col 6 is the vertical timing pattern; skip it
    for step = 0, n-1 do
      local row = going_up and (n-1-step) or step
      for dc = 0, 1 do
        local c = col-dc
        if m[row][c] == nil then  -- nil means no function pattern here
          m[row][c] = (bi <= #bits) and bits[bi] or 0
          bi = bi+1
        end
      end
    end
    going_up = not going_up
    col = col-2
  end

  return m, n
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Masking: XOR data modules with one of 8 patterns; keep the lowest-penalty result.
-- ─────────────────────────────────────────────────────────────────────────────

local MASK_FN = {
  function(r,c) return (r+c)%2==0 end,
  function(r,_) return r%2==0 end,
  function(_,c) return c%3==0 end,
  function(r,c) return (r+c)%3==0 end,
  function(r,c) return (r//2+c//3)%2==0 end,
  function(r,c) return (r*c)%2+(r*c)%3==0 end,
  function(r,c) return ((r*c)%2+(r*c)%3)%2==0 end,
  function(r,c) return ((r+c)%2+(r*c)%3)%2==0 end,
}

local function apply_mask(m, n, ver, mask_id)
  local fn = MASK_FN[mask_id+1]
  local nm = new_mat(n)
  for r = 0, n-1 do
    for c = 0, n-1 do
      local v = m[r][c] or 0
      -- XOR only data modules; leave function patterns (finders, timing, …) alone
      if not is_func(ver, n, r, c) and fn(r,c) then v = v~1 end
      nm[r][c] = v
    end
  end
  return nm
end

-- Evaluates how "scanner-friendly" a masked matrix is.  Lower score = better.
-- We implement three of the four ISO 18004 penalty rules:
--   Rule 1: long runs of same-colour modules in a row or column (+3 for run of 5,
--           +1 for each additional module).  Runs confuse edge detectors.
--   Rule 2: 2×2 blocks of same colour (+3 each). Solid areas look like finders.
--   Rule 4: deviation from 50% dark-module ratio (+10 per 5% step away from 50%).
--           A balanced symbol is easier to threshold under varying lighting.
-- Rule 3 (finder-like subsequences) is omitted; the chosen mask is still good.
local function penalty(m, n)
  local p = 0

  for r = 0, n-1 do
    local function scan_run(get)
      local run, cur = 0, -1
      for i = 0, n-1 do
        local v = get(r,i)
        if v == cur then
          run=run+1
          if run==5 then p=p+3 elseif run>5 then p=p+1 end
        else
          cur=v; run=1
        end
      end
    end
    scan_run(function(r,c) return m[r][c] end)   -- horizontal scan
    scan_run(function(r,c) return m[c][r] end)   -- vertical scan (swap indices)
  end

  for r = 0, n-2 do
    for c = 0, n-2 do
      local v = m[r][c]
      if v==m[r][c+1] and v==m[r+1][c] and v==m[r+1][c+1] then p=p+3 end
    end
  end

  local dark = 0
  for r = 0, n-1 do for c = 0, n-1 do if m[r][c]==1 then dark=dark+1 end end end
  local pct = dark*100//(n*n)
  -- ISO 18004 Rule 4: find the two nearest multiples of 5 on either side of pct,
  -- compute each one's distance from 50%, take the minimum, scale by 10.
  local snap = pct - pct % 5
  p = p + math.min(math.abs(snap - 50), math.abs(snap + 5 - 50)) // 5 * 10

  return p
end

-- ─────────────────────────────────────────────────────────────────────────────
-- High-level QR matrix generator
-- ─────────────────────────────────────────────────────────────────────────────

local function qr_matrix(text)
  -- Choose the smallest version whose byte-mode capacity fits the text.
  -- CAP_L[25] = 1273 is the absolute ceiling; JWT payloads from init-qr-code are
  -- typically ~840 bytes (version 20), but the upper bound is guarded explicitly.
  if #text > CAP_L[25] then
    error(string.format(
      "JWT zu lang für QR-Code (%d Bytes, max. %d für Version 25 EC-L).", #text, CAP_L[25]))
  end
  local ver = 1
  for v = 1, 25 do
    if CAP_L[v] and CAP_L[v] >= #text then ver=v; break end
  end

  local cw = encode_data(text, ver)
  -- Build the base matrix: all function patterns + data, but NO format/mask yet.
  local m_base, n = build_matrix(ver, cw)

  -- Try all 8 masks, score each, keep the matrix with the lowest penalty.
  -- Format info (which encodes the mask number) is placed here temporarily for
  -- scoring purposes; the winning copy is kept in best_m.
  local best_m, best_p = nil, math.huge
  for mask = 0, 7 do
    local mm = apply_mask(m_base, n, ver, mask)
    place_format(mm, n, format_info_word(mask))
    local p = penalty(mm, n)
    if p < best_p then best_m, best_p = mm, p end
  end

  -- Version information (two 6×3 rectangles, only for QR code version 7 and above).
  -- Written last because it doesn't interact with masking.
  if ver >= 7 then
    local vi = version_info_word(ver)
    for i = 0, 2 do for j = 0, 5 do
      local bit = (vi >> (j*3+i)) & 1
      best_m[n-11+i][j] = bit  -- bottom-left block
      best_m[j][n-11+i] = bit  -- top-right block
    end end
  end

  return best_m, n
end

-- ─────────────────────────────────────────────────────────────────────────────
-- PNG encoding (8-bit grayscale, DEFLATE store mode — no compression lib available)
-- ─────────────────────────────────────────────────────────────────────────────

local CRC_TABLE = {}
do
  -- Build a standard CRC-32 lookup table (polynomial 0xEDB88320, reflected form).
  for i = 0, 255 do
    local c = i
    for _ = 1, 8 do
      c = (c&1==1) and (0xEDB88320 ~ (c>>1)) or (c>>1)
    end
    CRC_TABLE[i] = c
  end
end

local function crc32(data)
  local crc = 0xFFFFFFFF
  for i = 1, #data do
    crc = CRC_TABLE[(crc~string.byte(data,i))&0xFF] ~ (crc>>8)
  end
  return (crc~0xFFFFFFFF) & 0xFFFFFFFF
end

-- Adler-32: a simpler running-sum checksum used inside the zlib wrapper.
-- s1 = sum of all bytes + 1; s2 = sum of all s1 values. Both mod 65521 (prime).
local function adler32(data)
  local s1, s2 = 1, 0
  for i = 1, #data do
    s1 = (s1 + string.byte(data,i)) % 65521
    s2 = (s2 + s1) % 65521
  end
  return (s2<<16) | s1
end

local function be4(v)  -- big-endian 4-byte encoding (used for PNG lengths/CRCs)
  return string.char((v>>24)&0xFF,(v>>16)&0xFF,(v>>8)&0xFF,v&0xFF)
end

local function png_chunk(typ, data)
  return be4(#data) .. typ .. data .. be4(crc32(typ..data))
end

local function make_png(pixels, w, h)
  -- Prepend filter-type byte 0x00 (None) to each row before feeding into DEFLATE.
  local rows = {}
  for y = 0, h-1 do
    rows[#rows+1] = "\0" .. pixels:sub(y*w+1, (y+1)*w)
  end
  local raw = table.concat(rows)
  local a32 = adler32(raw)

  -- DEFLATE store: 0x78 0x01 = zlib header (CMF=deflate, FLG=default compression).
  -- Each uncompressed block: 1-byte BFINAL/BTYPE | 2-byte LEN | 2-byte NLEN | data.
  -- LEN max is 65535; 65534 is used to avoid edge cases with the NLEN complement.
  local parts = {"\x78\x01"}
  local i = 1
  while i <= #raw do
    local len = math.min(65534, #raw-i+1)
    local last = (i+len-1 >= #raw) and 1 or 0  -- BFINAL=1 on last block
    local nlen = (~len) & 0xFFFF                -- one's complement of len
    parts[#parts+1] = string.char(last, len&0xFF, (len>>8)&0xFF, nlen&0xFF, (nlen>>8)&0xFF)
    parts[#parts+1] = raw:sub(i, i+len-1)
    i = i+len
  end
  parts[#parts+1] = be4(a32)  -- Adler-32 trailer closes the zlib stream
  local idat = table.concat(parts)

  local ihdr = string.char(
    (w>>24)&0xFF,(w>>16)&0xFF,(w>>8)&0xFF,w&0xFF,
    (h>>24)&0xFF,(h>>16)&0xFF,(h>>8)&0xFF,h&0xFF,
    8, 0, 0, 0, 0  -- bit depth=8, colour type=0 (grayscale), no interlace
  )
  return "\x89PNG\r\n\x1a\n"
      .. png_chunk("IHDR", ihdr)
      .. png_chunk("IDAT", idat)
      .. png_chunk("IEND", "")
end

-- ─────────────────────────────────────────────────────────────────────────────
-- QR code → PNG image
-- ─────────────────────────────────────────────────────────────────────────────

local function qr_png(text, scale, quiet)
  scale = scale or 4
  quiet = quiet or 4
  local mat, n = qr_matrix(text)
  local sz = (n + 2*quiet) * scale
  local dark_px  = string.rep("\0",   scale)
  local light_px = string.rep("\xFF", scale)
  local pixel_parts = {}
  for row = -quiet, n+quiet-1 do
    local row_pixels = {}
    for col = -quiet, n+quiet-1 do
      local is_dark = (row >= 0 and row < n and col >= 0 and col < n
                       and mat[row] and mat[row][col] == 1)
      row_pixels[#row_pixels+1] = is_dark and dark_px or light_px
    end
    local row_str = table.concat(row_pixels)
    -- Repeat each pixel-row `scale` times to produce square modules.
    for _ = 1, scale do pixel_parts[#pixel_parts+1] = row_str end
  end
  return make_png(table.concat(pixel_parts), sz, sz)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Utilities
-- ─────────────────────────────────────────────────────────────────────────────

-- Pseudo-random UUID v4 for the OAuth state parameter.
-- Collision probability is negligible for single-user interactive sessions.
local function uuid()
  local t = {}
  for i = 1, 32 do t[i] = string.format("%x", math.random(0,15)) end
  table.insert(t, 9,  "-"); table.insert(t, 14, "-")
  table.insert(t, 19, "-"); table.insert(t, 24, "-")
  return table.concat(t)
end

-- ─────────────────────────────────────────────────────────────────────────────
-- Session state (module-level; persists across InitializeSession2 phases)
-- ─────────────────────────────────────────────────────────────────────────────

local g_jwt          = nil   -- QR challenge JWT (used to poll status and call qr-login)
local g_qr_url       = nil   -- SecureGo plus login URL encoded in the QR image
local g_phase        = 0     -- counts how many times InitializeSession2 has been called
local g_access_token = nil   -- portal access_token, set when TOKEN_ENDPOINT returns JSON (not cookies)

-- ─────────────────────────────────────────────────────────────────────────────
-- MoneyMoney extension
-- ─────────────────────────────────────────────────────────────────────────────

WebBanking {
  version     = 1.0,
  url         = "https://banking.umweltbank.de",
  services    = {"Umweltbank Depot"},
  description = "Umweltbank Depot-Konten via QR-Code / SecureGo plus",
}

local connection = Connection()

function SupportsBank(protocol, bankCode)
  return protocol == ProtocolWebBanking and bankCode == "Umweltbank Depot"
end

-- Returns the Location header of a redirect response without following it.
-- connection.redirects = false suppresses automatic redirect following;
-- connection:get() returns headers as its 5th value regardless.
local function get_redirect_location(url)
  connection.redirects = false
  local ok, _, _, _, _, headers = pcall(function()
    return connection:get(url)
  end)
  connection.redirects = true
  if not ok then return nil end
  return headers and headers["Location"]
end

-- Walks a redirect chain one hop at a time until a URL matching targetPrefix
-- is found, then returns it.  Used to extract portal/login?code=X without
-- MoneyMoney consuming the URL by following the redirect automatically.
local function follow_to_portal_code(start_url)
  local url = start_url
  for _ = 1, 10 do
    local loc = get_redirect_location(url)
    if not loc then return nil end
    if loc:find(REDIRECT_URI, 1, true) == 1 then return loc end
    url = loc
  end
  return nil
end

local function qr_challenge()
  local png = type(renderQrCodePng) == "function"
    and renderQrCodePng(g_qr_url, 600)
    or  qr_png(g_qr_url, 10, 4)
  return {title = "Umweltbank QR-Login", challenge = png, poll = true}
end

-- MoneyMoney calls InitializeSession2 repeatedly due to poll=true.
-- Phase 1 sets up the session and emits the QR challenge.
-- Phase 2+ polls the approval status; on APPROVED the auth chain completes.
function InitializeSession2(protocol, bank, username, reserved, password)
  g_phase = g_phase + 1

  -- ── Phase 1: start CAS session and emit QR challenge ─────────────────────
  if g_phase == 1 then
    -- Primes the portal-oauth state and sets the CAS_SESSION cookie.
    connection:get(AUTHORIZE_ENDPOINT
      .. "?response_type=code&client_id=online-banking"
      .. "&redirect_uri=" .. MM.urlencode(REDIRECT_URI))

    local ui_data = JSON(connection:get(QR_INIT_UI_ENDPOINT)):dictionary()
    if ui_data["qrCodeLoginAllowed"] == false then
      error("QR-Code Login ist noch nicht aktiviert.\n\n"
          .. "Bitte öffnen Sie banking.umweltbank.de im Browser, melden Sie sich "
          .. "an und aktivieren Sie den QR-Code Login unter Einstellungen → "
          .. "SecureGo plus. Danach kann diese Erweiterung genutzt werden.")
    end

    local data = JSON(connection:request("POST", QR_INIT_CODE_ENDPOINT, "", "", {
      ["Origin"] = BASE, ["Referer"] = BASE .. "/",
    })):dictionary()
    g_jwt = data["qrCodeJwt"]
    if not g_jwt or g_jwt == "" then
      error("QR-Code konnte nicht abgerufen werden.")
    end

    g_qr_url = string.gsub(ui_data["qrCodeUrl"], "{JWT}", g_jwt)
    return qr_challenge()

  -- ── Phase 2+: poll status, complete auth on APPROVED ─────────────────────
  else
    local state = JSON(connection:request("GET", QR_STATUS_ENDPOINT, nil, nil,
      {["Authorization"] = "Bearer " .. g_jwt})):dictionary()["state"]

    if state == nil or state == "RETRY" then
      return qr_challenge()  -- still waiting for scan, keep polling
    elseif state == "REJECTED" or state == "CANCELLED" then
      error("QR-Code Login wurde in SecureGo plus abgelehnt. Bitte erneut versuchen.")
    elseif state == "EXPIRED" then
      error("QR-Code abgelaufen. Bitte die Anmeldung neu starten.")
    elseif state ~= "APPROVED" then
      error("QR-Authentifizierung: unbekannter Status '" .. state .. "'.")
    end

    -- Approved: advance CAS authentication state.
    local apr = JSON(connection:request("POST", QR_LOGIN_ENDPOINT, "{}", "application/json",
      {["Authorization"] = "Bearer " .. g_jwt})):dictionary()["authenticationProcessResponse"]
    if not apr then error("qr-login: unerwartete Antwort vom Server.") end

    if not apr["authenticationProcessCompleted"] then
      local ns = apr["nextAuthenticationProcessStep"]
      if ns then
        for _, a in ipairs(ns["actions"] or {}) do
          if a["stepType"] == "QR_CODE_FIRST_LOGIN" then
            error("Bitte aktivieren Sie den QR-Code Login zuerst einmal im Browser "
                .. "unter banking.umweltbank.de (Menü → QR-Code Login).")
          end
        end
      end
      error("QR-Authentifizierung nicht abgeschlossen.")
    end

    -- Finalize CAS; response body contains the callback params for portal-oauth/login.
    local cr = JSON(connection:request("POST", CONSENT_ENDPOINT,
      '{"useBrowserDetection":false}', "application/json")):dictionary()
    cr = cr["postAuthenticationProcessResponse"]
    cr = cr and cr["resultOfCurrentPostAuthenticationProcessStep"]
    local param_str = cr and cr["parameter"]
    if not param_str then
      error("Consent fehlgeschlagen: kein Weiterleitungsparameter erhalten.")
    end

    -- Walk the redirect chain manually to capture the portal code.
    -- With connection.redirects = false we can read each Location header:
    --   portal-oauth/login → portal-oauth/oauth/authorize → portal/login?code=X
    local portal_url = follow_to_portal_code(CAS_REDIRECT_URI .. "?" .. param_str)
    local portal_code = portal_url and portal_url:match("[?&]code=([^&]+)")
    if not portal_code then
      error("Portal-Code nicht gefunden in der Redirect-Kette.")
    end

    -- Exchange portal code for session tokens / HttpOnly cookies.
    local tok_resp = connection:request("POST", TOKEN_ENDPOINT,
      "grant_type=authorization_code"
        .. "&code=" .. portal_code
        .. "&client_id=online-banking"
        .. "&redirect_uri=" .. MM.urlencode(REDIRECT_URI),
      "application/x-www-form-urlencoded")
    local tok_data = {}
    local parse_ok = pcall(function() tok_data = JSON(tok_resp):dictionary() end)
    if parse_ok and tok_data["access_token"] then
      g_access_token = tok_data["access_token"]
    elseif parse_ok and tok_data["error"] then
      error("Token-Austausch fehlgeschlagen: "
          .. (tok_data["error_description"] or tok_data["error"]))
    end
    -- TOKEN_ENDPOINT may return HttpOnly cookies instead of JSON; the cookie jar
    -- handles those automatically.
  end
end

local function api_headers()
  local h = {["X-VP-App-Locale"] = "de-DE"}
  if g_access_token then h["Authorization"] = "Bearer " .. g_access_token end
  return h
end

function ListAccounts(knownAccounts)
  local resp = connection:get(KONTO_GROUP_ENDPOINT, api_headers())
  local data = JSON(resp):dictionary()

  local accounts = {}
  for _, grp in ipairs(data["groups"] or {}) do
    for _, konto in ipairs(grp["konten"] or {}) do
      if konto["art"] == "DEPOT" then
        accounts[#accounts+1] = {
          name          = konto["displayName"] or konto["bezeichnung"] or "Umweltbank Depot",
          accountNumber = konto["businessIdent"] or konto["kontonummer"] or konto["iban"]
                       or (konto["nummer"] and tostring(konto["nummer"])) or "",
          currency      = "EUR",
          portfolio     = true,
          type          = AccountTypePortfolio,
          ident         = konto["ident"],
        }
      end
    end
  end
  if #accounts == 0 then
    error("Kein Depot-Konto in konto/group gefunden (art == 'DEPOT').")
  end
  if #accounts > 1 then
    -- aktuellekurse is session-scoped; the request carries no per-account selector,
    -- so RefreshAccount would return identical holdings for every depot. Return only
    -- the first to avoid silently duplicating positions across multiple accounts.
    return {accounts[1]}
  end
  return accounts
end

function RefreshAccount(account, since)
  local depot_nr = account and account.accountNumber or ""

  -- GET depots/{nr} returns positions with last-trading-day prices (kursAktuell).
  -- depotwert is always 0 from the API; we sum kurswertEUR across positions instead.
  local resp    = connection:get(DEPOTS_ENDPOINT .. depot_nr, api_headers())
  local data    = JSON(resp):dictionary()
  local payload = data["payload"]
  if not payload then
    error("GET depots/" .. depot_nr .. ": keine Payload in der Antwort.")
  end

  local securities  = {}
  local total_value = 0
  for _, pos in ipairs(payload["positionen"] or {}) do
    local kd     = pos["kursdaten"] or {}
    local boerse = kd["kursAktuellBoerse"] or {}
    local val    = tonumber(pos["kurswertEUR"]) or 0
    total_value  = total_value + val
    securities[#securities+1] = {
      name          = tostring(pos["kurzbezeichnung"] or ""),
      isin          = tostring(pos["isin"] or ""),
      wkn           = tostring(pos["wkn"] or ""),
      quantity      = tonumber(pos["stueckNominal"]) or 0,
      amount        = val,
      currency      = tostring(pos["gattungsWaehrung"] or "EUR"),
      purchasePrice = tonumber(pos["durchschnittlicherEinstandskurs"]) or 0,
      price         = tonumber(kd["kursAktuell"]) or 0,
      exchangeName  = tostring(boerse["langbezeichnung"] or ""),
    }
  end

  return {
    balance    = total_value,
    currency   = "EUR",
    securities = securities,
  }
end

function EndSession()
  g_jwt          = nil
  g_qr_url       = nil
  g_phase        = 0
  g_access_token = nil
end
