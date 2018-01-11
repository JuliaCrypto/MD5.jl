# Nonlinear functions, in order to encourage inlining, these sadly are not an array of lambdas
f_round0(b,c,d) = SHA.Round0(b,c,d) #UInt32((b & c) | (~b & d))
f_round1(b,c,d) = UInt32((b & d) | (c & ~d))
f_round2(b,c,d) = SHA.Round1And3(b,c,d) # return UInt32(b ⊻ c ⊻ d) #xors
f_round3(b,c,d) = UInt32(c ⊻ (b | ~d))

g_round0(i) = i
g_round1(i) = (5i+1) % 16
g_round2(i) = (3i + 5) % 16
g_round3(i) = 7i % 16


function conclude_round(a,b,c,d,f,g,pbuf,i)
    @inbounds s = ss[i+1]
    @inbounds k = kk[i+1]
    @inbounds m = unsafe_load(pbuf, g+1)
    f = f + a + k + m
    a = d
    d = c
    c = b
    b = b + lrot(s,f, 32)
    a,b,c,d
end

transform!(ctx::MD5_CTX) = transform_unrolled!(ctx)

function transform_baseline!(context::MD5_CTX)
   pbuf = buffer_pointer(context)
   a,b,c,d = context.state
     
   for i in 0:15
        f = f_round0(b,c,d)
        g = g_round0(i)
        a,b,c,d = conclude_round(a, b, c, d, f, g, pbuf, i)
   end
   for i in 16:31
        f = f_round1(b,c,d)
        g = g_round1(i)
        a,b,c,d = conclude_round(a, b, c, d, f, g, pbuf, i)
   end
   for i in 32:47
        f = f_round2(b,c,d)
        g = g_round2(i)
        a,b,c,d = conclude_round(a, b, c, d, f, g, pbuf, i)
   end
   for i in 48:63
        f = f_round3(b,c,d)
        g = g_round3(i)
        a,b,c,d = conclude_round(a, b, c, d, f, g, pbuf, i)
    end
    @inbounds context.state .+= [a,b,c,d]
end

@generated function transform_unrolled!(context::MD5_CTX)
    ret = quote
        pbuf = buffer_pointer(context)
    end
    ex  = quote
        A = context.state[1]
        B = context.state[2]
        C = context.state[3]
        D = context.state[4]
    end
    push!(ret.args, ex)
    for i in 0:63
        if 0 ≤ i ≤ 15
            ex = :(F = (B & C) | ((~B) & D))
            g = i
        elseif 16 ≤ i ≤ 31
            ex = :(F = (D & B) | ((~D) & C))
            g = 5i + 1
        elseif 32 ≤ i ≤ 47
            ex = :(F = B ⊻ C ⊻ D)
            g = 3i + 5
        elseif 48 ≤ i ≤ 63
            ex = :(F = C ⊻ (B | (~D)))
            g = 7i
        end
        push!(ret.args, ex)
        g = (g % 16) + 1
        ex = quote
            temp = D
            D = C
            C = B
            inner = A + F + $(kk[i+1]) + unsafe_load(pbuf, $g)
            rot_inner = lrot($(ss[i+1]), inner, 32)
            B = B + rot_inner
            A = temp
        end
        push!(ret.args, ex)
    end

    ex = quote
        context.state[1] += A
        context.state[2] += B
        context.state[3] += C
        context.state[4] += D
    end
    push!(ret.args, ex)
    quote
        @inbounds $ret
    end
end

function digest!(context::T) where {T<:MD5_CTX}
    pad_remainder!(context)

    bitcount_idx = div(short_blocklen(T), sizeof(context.bytecount)) + 1
    pbuf = Ptr{typeof(context.bytecount)}(pointer(context.buffer))
    unsafe_store!(pbuf, 8context.bytecount, bitcount_idx)

    # Final transform:
    transform!(context)

    # ctx has been mutated
    reinterpret(UInt8, context.state)
end
