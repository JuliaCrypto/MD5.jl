# MD5

[![Build Status](https://travis-ci.org/oxinabox/MD5.jl.svg?branch=master)](https://travis-ci.org/oxinabox/MD5.jl)

[![Coverage Status](https://coveralls.io/repos/oxinabox/MD5.jl/badge.svg?branch=master&service=github)](https://coveralls.io/github/oxinabox/MD5.jl?branch=master)

[![codecov.io](http://codecov.io/github/oxinabox/MD5.jl/coverage.svg?branch=master)](http://codecov.io/github/oxinabox/MD5.jl?branch=master)


A pure julia MD5 implementation.
There is few reasons to create new MD5 checksums, but there are a huge number of existing ones.
Honestly, just use SHA-256 for everything you would use MD5 for.
MD5 is not secure, and it's not faster, and it doesn't have much going for it.


With that said, this is an MD5 implementation.

It directly extends [SHA.jl](https://github.com/staticfloat/SHA.jl).
Using a lot of the same underlying functionality, and it's interface.

Just like the functions from SHA.jl
`md5` takes either an `Array{UInt8}`, a `String`, or an `IO` object.
This makes it trivial to checksum a file.


```
julia> using MD5

julia> bytes2hex(md5("test"))
"098f6bcd4621d373cade4e832627b4f6"

julia> String(read("test.txt"))
"test\n"

julia> open(md5, "test.txt")
16-element Array{UInt8,1}:
 0xd8
 0xe8
 0xfc
 0xa2
 0xdc
 0x0f
 0x89
 0x6f
 0xd7
 0xcb
 0x4c
 0xb0
 0x03
 0x1b
 0xa2
 0x49
```
