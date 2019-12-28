using MD5: MD5
using Nettle: Nettle
using BenchmarkTools

data = randstring(10^4)

@show Nettle.hexdigest("md5", data)
display(@btime Nettle.hexdigest("md5", data))
println()

@show bytes2hex(MD5.md5(data))
display(@btime MD5.md5(data))
println()

