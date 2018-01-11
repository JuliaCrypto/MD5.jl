import MD5
using BenchmarkTools

data = randstring(10^4)

if Pkg.installed("Nettle") != nothing
import Nettle
@show Nettle.hexdigest("md5", data)
display(@benchmark Nettle.hexdigest("md5", data))
    println()
end

@show bytes2hex(MD5.md5(data))
display(@benchmark MD5.md5(data))
println()

