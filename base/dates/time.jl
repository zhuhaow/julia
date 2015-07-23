# This file is a part of Julia. License is MIT: http://julialang.org/license

immutable Time
    value::Nanosecond
end

NS(x) = Nanosecond(x)
value(x::Time) = x.value.value

function Time(h::Int64=0,m::Int64=0,s::Int64=0,millis::Int64=0,micros::Int64=0,nanos::Int64=0)
    -1 < h < 24 || throw(ArgumentError("Hour: $h out of range (0:23)"))
    -1 < m < 60 || throw(ArgumentError("Minute: $m out of range (0:59)"))
    -1 < s < 60 || throw(ArgumentError("Second: $s out of range (0:59)"))
    -1 < millis < 1000 || throw(ArgumentError("Millisecond: $millis out of range (0:999)"))
    -1 < micros < 1000 || throw(ArgumentError("Microsecond: $micros out of range (0:999)"))
    -1 < nanos < 1000 || throw(ArgumentError("Nanosecond: $nanos out of range (0:999)"))
    return Time(NS(nanos + 1000*micros + Int64(1000000)*millis + Int64(1000000000)*s + Int64(60000000000)*m + Int64(3600000000000)*h))
end

Time(h::Hour,m::Minute=Minute(0),s::Second=Second(0),
    millis::Millisecond=Millisecond(0),
    micros::Microsecond=Microsecond(0),
    nanos::Nanosecond=Nanosecond(0)) = Time(Int64(h),Int64(m),Int64(s),Int64(millis),Int64(micros),Int64(nanos))
_c(c) = convert(Int64,c)
Time(h,m=0,s=0,millis=0,micros=0,nanos=0) = Time(_c(h),_c(m),_c(s),_c(millis),_c(micros),_c(nanos))

Base.isfinite{T<:Time}(::Union(Type{T},T)) = true
Base.eps(t::Time) = Nanosecond(1)
Base.typemax(::Union(Time,Type{Time})) = Time(23,59,59,999,999,999)
Base.typemin(::Union(Time,Type{Time})) = Time(0,0,0,0)
Base.isless(x::Time,y::Time) = isless(value(x),value(y))
==(x::Time,y::Time) = ===(value(x),value(y))

hour(t::Time)   = mod(fld(value(t),3600000000000),24)
minute(t::Time) = mod(fld(value(t),60000000000),60)
second(t::Time) = mod(fld(value(t),1000000000),60)
millisecond(t::Time) = mod(fld(value(t),1000000),1000)
microsecond(t::Time) = mod(fld(value(t),1000),1000)
nanosecond(t::Time) = mod(value(t),1000)

tons(x) = Dates.toms(x) * 1000000
tons(x::Microsecond) = x * 1000
tons(x::Nanosecond) = x

(+)(x::Time,y::Dates.TimePeriod)   = return Time(NS(value(x)+Dates.tons(y)))
(-)(x::Time,y::Dates.TimePeriod)   = return Time(NS(value(x)-Dates.tons(y)))
(+)(y::Dates.TimePeriod,x::Time) = x + y
(-)(y::Dates.TimePeriod,x::Time) = x - y

function Base.string(t::Time)
    h,mi,s = hour(t),minute(t),second(t)
    hh = lpad(h,2,"0")
    mii = lpad(mi,2,"0")
    ss = lpad(s,2,"0")
    ms = millisecond(t) == 0 ? "" : string(millisecond(t)/1000.0)[2:end]
    return "$hh:$mii:$ss$(ms)"
end
Base.show(io::IO,x::Time) = print(io,string(x))
