using Base: @deprecate
import Base: copy
@deprecate copy(ctx::MD5_CTX) deepcopy(ctx)
