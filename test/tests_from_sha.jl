# These tests are utterly stolen from https://github.com/staticfloat/SHA.jl
using SHA
import Nettle

md5(x) = digest(

# Define some data we will run our tests on
lorem = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum."
so_many_as_array = repmat([0x61], 1000000)
so_many_as_tuple = ntuple((i) -> 0x61, 1000000)
file = "sha"  # Subject to change
fIO = open(file, "w")
write(fIO, '\0')
close(fIO)
data = Any["", "test", lorem, file, so_many_as_array, so_many_as_tuple]

# Descriptions of the data, the SHA functions we'll run on the data, etc...
data_desc = ["the empty string", "the string \"test\"", "lorem ipsum",
             "0 file", "one million a's Array", "one million a's Tuple"]
sha_types = Dict(md5=>MD5_CTX)
sha_funcs = [md5]
ctxs = [MD5_CTX]
shws = ["MD5 hash state"]

answers = Dict(md5=>[
                    "","","",
                   "","",""]
)

function describe_hash{S<:SHA.SHA_CTX}(T::Type{S})
    "MD5"
end

println("Loaded hash types: $(join(sort([describe_hash(t[2]) for t in sha_types]), ", ", " and "))")

# First, test processing the data in one go
nerrors = 0
for idx in 1:length(data)
    desc = data_desc[idx]
    print("Testing on $desc$(join(["." for z in 1:(34-length(desc))]))")
    nerrors_old = nerrors
    for sha_idx in 1:length(sha_funcs)
        sha_func = sha_funcs[sha_idx]

        if idx == 4
            open(data[idx]) do f
                hash = bytes2hex(sha_func(f))
            end
        else
            hash = bytes2hex(sha_func(data[idx]))
        end

        if hash != answers[sha_func][idx]
            print("\n")
            warn(
            """
            For $(describe_hash(sha_types[sha_func])) expected:
                $(answers[sha_func][idx])
            Calculated:
                $(hash)
            """)
            nerrors += 1
        else
            print(".")
        end
    end
    println("Done! [$(nerrors - nerrors_old) errors]")
end

# Do another test on the "so many a's" data where we chunk up the data into
# two chunks, (sized appropriately to AVOID overflow from one update to another)
# in order to test multiple update!() calls
print("Testing on one million a's (chunked properly)")
nerrors_old = nerrors
for sha_idx in 1:length(sha_funcs)
    ctx = sha_types[sha_funcs[sha_idx]]()
    SHA.update!(ctx, so_many_as_array[1:2*SHA.blocklen(typeof(ctx))])
    SHA.update!(ctx, so_many_as_array[2*SHA.blocklen(typeof(ctx))+1:end])
    hash = bytes2hex(SHA.digest!(ctx))
    if hash != answers[sha_funcs[sha_idx]][end]
        print("\n")
        warn(
        """
        For $(describe_hash(sha_types[sha_funcs[sha_idx]])) expected:
            $(answers[sha_funcs[sha_idx]][end-1])
        Calculated:
            $(hash)
        """)
        nerrors += 1
    else
        print(".")
    end
end
println("Done! [$(nerrors - nerrors_old) errors]")

# Do another test on the "so many a's" data where we chunk up the data into
# three chunks, (sized appropriately to CAUSE overflow from one update to another)
# in order to test multiple update!() calls as well as the overflow codepaths
print("Testing on one million a's (chunked clumsily)")
nerrors_old = nerrors
for sha_idx in 1:length(sha_funcs)
    ctx = sha_types[sha_funcs[sha_idx]]()

    # Get indices awkwardly placed for the blocklength of this hash type
    idx0 = round(Int, 0.3*SHA.blocklen(typeof(ctx)))
    idx1 = round(Int, 1.7*SHA.blocklen(typeof(ctx)))
    idx2 = round(Int, 2.6*SHA.blocklen(typeof(ctx)))

    # Feed data in according to our dastardly blocking scheme
    SHA.update!(ctx, so_many_as_array[0      + 1:1*idx0])
    SHA.update!(ctx, so_many_as_array[1*idx0 + 1:2*idx0])
    SHA.update!(ctx, so_many_as_array[2*idx0 + 1:3*idx0])
    SHA.update!(ctx, so_many_as_array[3*idx0 + 1:4*idx0])
    SHA.update!(ctx, so_many_as_array[4*idx0 + 1:idx1])
    SHA.update!(ctx, so_many_as_array[idx1 + 1:idx2])
    SHA.update!(ctx, so_many_as_array[idx2 + 1:end])

    # Ensure the hash is the appropriate one
    hash = bytes2hex(SHA.digest!(ctx))
    if hash != answers[sha_funcs[sha_idx]][end]
        print("\n")
        warn(
        """
        For $(describe_hash(sha_types[sha_funcs[sha_idx]])) expected:
            $(answers[sha_funcs[sha_idx]][end-1])
        Calculated:
            $(hash)
        """)
        nerrors += 1
    else
        print(".")
    end
end
println("Done! [$(nerrors - nerrors_old) errors]")

if VERSION >= v"0.7.0-DEV.1472"
    replstr(x) = sprint((io, x) -> show(IOContext(io, :limit => true), MIME("text/plain"), x), x)
else
    replstr(x) = sprint((io, x) -> show(IOContext(io, limit=true), MIME("text/plain"), x), x)
end

for idx in 1:length(ctxs)
    # Part #1: copy
    print("Testing copy function @ $(ctxs[idx]) ...")
    try
        copy(ctxs[idx]())
    catch
        print("\n")
        warn("Some weird copy error happened with $(ctxs[idx])")
        nerrors += 1
    end
    println("Done! [$(nerrors - nerrors_old) errors]")

    # Part #2: show
    print("Testing show function @ $(ctxs[idx]) ...")
    if replstr(ctxs[idx]()) != shws[idx]
        print("\n")
        warn("Some weird show error happened with $(ctxs[idx])")
        nerrors += 1
    end
    println("Done! [$(nerrors - nerrors_old) errors]")
end

# test error if eltype of input is not UInt8
for f in sha_funcs
    try
        f(UInt32[0x23467, 0x324775])
        warn("Non-UInt8 Arrays should fail")
        nerrors += 1
    end
end


# Clean up the I/O mess
rm(file)

if nerrors == 0
    println("ALL OK")
else
    println("Failed with $nerrors failures")
end
exit(nerrors)
