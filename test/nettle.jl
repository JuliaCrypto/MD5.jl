import Nettle

function test_equal_state(m::MD5.MD5_CTX,n::Nettle.Hasher)
    @test (n.state)[1:16] == reinterpret(UInt8, m.state)
end

@testset "Against Nettle initialize, update!, digest!" begin
    for chunkcount ∈ [0,1,2,3, 10, 100]
        m = MD5.MD5_CTX()
        n = Nettle.Hasher("md5")
        test_equal_state(m,n)
        for _ in 1:chunkcount
            chunksize = rand(0:10000)
            data = rand(UInt8, chunksize)
            test_equal_state(m, n)
            MD5.update!(m, data)
            Nettle.update!(n, data)
            test_equal_state(m,n)
        end
        @test MD5.digest!(m) == Nettle.digest!(n)
    end
end

@testset "Against Nettle end to end" begin
    for offset ∈ [0,10^3, 10^4, 10^5]
        iter = offset:(offset+1000)
        for l ∈ iter
            s = randstring(l)
            @test Nettle.hexdigest("md5", s) == bytes2hex(md5(s))
        end
    end
end
