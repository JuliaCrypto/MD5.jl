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


function transform!(context::MD5_CTX)
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
