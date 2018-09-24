# redundant imports, so this file can be run standalone
using Test
import MD5
using Random


import Nettle


function test_equal_state(md5_value::MD5.MD5_CTX,nettle_value::Nettle.Hasher)
    @test nettle_value.state[1:16] ==
        reinterpret(UInt8, md5_value.state)
end

@testset "Against Nettle initialize, update!, digest!" begin
    for _ in 1:10, chunkcount in [0,1,2,3, 10, 100]
        md5_value = MD5.MD5_CTX()
        nettle_value = Nettle.Hasher("md5")
        test_equal_state(md5_value, nettle_value)
        for _ in 1:chunkcount
            chunksize = rand(0:10000)
            data = rand(UInt8, chunksize)
            MD5.update!(md5_value, data)
            Nettle.update!(nettle_value, data)
            test_equal_state(md5_value,nettle_value)
        end
        @test MD5.digest!(md5_value) == Nettle.digest!(nettle_value)
    end
end

@testset "Against Nettle end to end" begin
    for offset in [0,10^3, 10^4, 10^5]
        iter = offset:(offset+1000)
        for l in iter
            s = randstring(l)
            @test Nettle.hexdigest("md5", s) == bytes2hex(md5(s))
        end
    end
end

