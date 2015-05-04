# This file is a part of Julia. License is MIT: http://julialang.org/license

using Base.Test
import Base.LinAlg: BlasFloat, BlasComplex

debug = false

n=12 #Size of matrix problem to test
srand(1)

debug && println("Diagonal matrices")
for relty in (Float32, Float64, BigFloat), elty in (relty, Complex{relty})
    debug && println("elty is $(elty), relty is $(relty)")
    d=convert(Vector{elty}, randn(n))
    v=convert(Vector{elty}, randn(n))
    U=convert(Matrix{elty}, randn(n,n))
    if elty <: Complex
        d+=im*convert(Vector{elty}, randn(n))
        v+=im*convert(Vector{elty}, randn(n))
        U+=im*convert(Matrix{elty}, randn(n,n))
    end
    D = Diagonal(d)
    DM = diagm(d)

    debug && println("Linear solve")
    @test_approx_eq_eps D*v DM*v n*eps(relty)*(elty<:Complex ? 2:1)
    @test_approx_eq_eps D*U DM*U n^2*eps(relty)*(elty<:Complex ? 2:1)
    if relty != BigFloat
        @test_approx_eq_eps D\v DM\v 2n^2*eps(relty)*(elty<:Complex ? 2:1)
        @test_approx_eq_eps D\U DM\U 2n^3*eps(relty)*(elty<:Complex ? 2:1)
    end

    debug && println("Simple unary functions")
    for func in (det, trace)
        @test_approx_eq_eps func(D) func(DM) n^2*eps(relty)*(elty<:Complex ? 2:1)
    end
    if relty <: BlasFloat
        for func in (expm,)
            @test_approx_eq_eps func(D) func(DM) n^3*eps(relty)
        end
    end
    if elty <: BlasComplex
        for func in (logdet, sqrtm)
            @test_approx_eq_eps func(D) func(DM) n^2*eps(relty)*2
        end
    end
    debug && println("Binary operations")
    d = convert(Vector{elty}, randn(n))
    D2 = Diagonal(d)
    DM2= diagm(d)
    for op in (+, -, *)
        @test_approx_eq full(op(D, D2)) op(DM, DM2)
    end

    #10036
    @test issym(D2)
    @test ishermitian(D2)
    if elty <: Complex
        dc = d + im*convert(Vector{elty}, ones(n))
        D3 = Diagonal(dc)
        @test issym(D3)
        @test !ishermitian(D3)
    end
end

#Issue #11120
let A11120 = Diagonal(Diagonal[Diagonal([1,2]), Diagonal([-3,4im]), Diagonal([-5])])
    @test svdvals(A11120) == [5:-1:1]
    @test full(A11120) == [
     1+0im  0+0im   0+0im  0+0im   0+0im
     0+0im  2+0im   0+0im  0+0im   0+0im
     0+0im  0+0im  -3+0im  0+0im   0+0im
     0+0im  0+0im   0+0im  0+4im   0+0im
     0+0im  0+0im   0+0im  0+0im  -5+0im]
    S11120 = svdfact(A11120)

    @test S11120[:U] == [
      0.0+0.0im    0.0+0.0im  0.0+0.0im      0.5+0.0im  0.0+0.0im
      0.0+0.0im    0.0+0.0im  0.0+0.0im      0.0+0.0im  2.0+0.0im
      0.0+0.0im   -0.75+0.0im 0.0+0.0im      0.0+0.0im  0.0+0.0im
      0.0+0.0im    0.0+0.0im  -4//3im        0.0+0.0im  0.0+0.0im
     -1.0+0.0im    0.0+0.0im  0.0+0.0im      0.0+0.0im  0.0+0.0im]
    @test S11120[:S] == [5:-1:1]
    @test S11120[:Vt] == [
      0.0+0.0im  0.0+0.0im  0.0+0.0im  0.0+0.0im  1.0+0.0im
      0.0+0.0im  0.0+0.0im  1.0+0.0im  0.0+0.0im  0.0+0.0im
      0.0+0.0im  0.0+0.0im  0.0+0.0im  1.0+0.0im  0.0+0.0im
      1.0+0.0im  0.0+0.0im  0.0+0.0im  0.0+0.0im  0.0+0.0im
      0.0+0.0im  1.0+0.0im  0.0+0.0im  0.0+0.0im  0.0+0.0im]
end

