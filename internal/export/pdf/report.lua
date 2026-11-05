-- YARS report theme: turns the report HTML's marked parts into the
-- template's LaTeX commands (report.latex). Values are escaped by pandoc's
-- LaTeX writer; colours are checked to be six hex digits.

local function tex(inlines)
  local s = pandoc.write(pandoc.Pandoc({ pandoc.Plain(inlines) }), 'latex')
  return (s:gsub('%s+$', ''))
end

local function str(s)
  if s == nil or s == '' then return '' end
  return tex({ pandoc.Str(s) })
end

-- the HTML reader keeps data-* attributes with or without their prefix
local function attr(el, k)
  return el.attributes[k] or el.attributes['data-' .. k] or ''
end

local function hex(s)
  if s ~= nil and s:match('^%x%x%x%x%x%x$') then return s end
  return 'E6E8EC'
end

local function raw(s) return pandoc.RawBlock('latex', s) end

-- spans of a block by their first class, in order
local function spans(el)
  local out = {}
  el:walk({
    Span = function(sp)
      local c = sp.classes[1]
      if c then
        out[c] = out[c] or {}
        table.insert(out[c], sp)
      end
    end,
  })
  return out
end

local function first(s, class)
  if s[class] and s[class][1] then return tex(s[class][1].content) end
  return ''
end

local function cover(div)
  local s = spans(div)
  local bar, counts, meta = {}, {}, {}
  for _, sp in ipairs(s['rp-seg'] or {}) do
    local w = tonumber(attr(sp, 'w')) or 0
    table.insert(bar, string.format('\\yarsseg{%s}{%.1f}', hex(attr(sp, 'color')), w))
    table.insert(counts, tex(sp.content))
  end
  for _, sp in ipairs(s['rp-m'] or {}) do
    table.insert(meta, string.format('\\yarsmeta{%s}{%s}', str(attr(sp, 'k')), tex(sp.content)))
  end
  return raw(string.format('\\yarscover{%s}{%s}{%s}{%s}{%s}{%s}{%s}',
    first(s, 'rp-brand'), first(s, 'rp-kicker'), first(s, 'rp-title'), first(s, 'rp-sub'),
    table.concat(bar), table.concat(counts, '\\hspace{5mm}'), table.concat(meta)))
end

local function fhead(div)
  local s = spans(div)
  return raw(string.format('\\yarsfinding{%s}{%s}{%s}{%s}{%s}{%s}{%s}',
    hex(attr(div, 'bg')), hex(attr(div, 'fg')), str(attr(div, 'sev'):upper()),
    first(s, 'rp-fid'), first(s, 'rp-ftitle'), first(s, 'rp-score'), first(s, 'rp-vec')))
end

local blocks = {
  Div = function(div)
    if div.classes:includes('rp-cover') then return cover(div) end
    if div.classes:includes('rp-fhead') then return fhead(div) end
  end,
  -- section names inside findings: small muted capitals, not in contents
  Header = function(h)
    if h.level == 2 then
      return raw('\\yarssub{' .. str(pandoc.utils.stringify(h.content):upper()) .. '}')
    end
  end,
  CodeBlock = function(cb)
    local text = cb.text:gsub('\\end{Verbatim}', '\\end {Verbatim}')
    return raw('\\begin{Verbatim}[breaklines,breakanywhere,fontsize=\\small,frame=leftline,framerule=2pt,rulecolor=\\color{yarsorange},framesep=3mm]\n'
      .. text .. '\n\\end{Verbatim}')
  end,
}

local inlines = {
  Span = function(sp)
    if sp.classes:includes('rp-sev') then
      return pandoc.RawInline('latex', string.format('\\yarstag{%s}{%s}{%s}',
        hex(attr(sp, 'bg')), hex(attr(sp, 'fg')), str(pandoc.utils.stringify(sp.content):upper())))
    end
  end,
}

return { blocks, inlines }
