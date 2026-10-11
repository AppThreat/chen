def run(cmd, shell: false)
  system(cmd)
end

def configure(opts)
  system(opts)
end

def collect(first, *rest, **kw)
  system(rest)
end

def forward(...)
  run(...)
end

def handle(source)
  run(source, shell: true)
  configure(name: source)
  collect(1, *source)
  collect(1, **source)
  forward(source)
end
