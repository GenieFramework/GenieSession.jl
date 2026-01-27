@safetestset "session cookie" begin
  using HTTP, Genie, Genie.Cookies
  using GenieSession

  # helper to pull out the raw “Set-Cookie” header string
  parse_setcookie(res::HTTP.Response)=first(
    filter(h->h.first=="Set-Cookie", res.headers)
  ).second

  # STEP 1: Start a new session → encrypted Set-Cookie
  req1, res1=HTTP.Request("GET", "/"), HTTP.Response()
  req1, res1, params1, sess1=GenieSession.start!(req1, res1)
  sid1=sess1.id
  ck1=parse_setcookie(res1)
  @test occursin("__geniesid=", ck1)

  # 1a) Decrypt cookie back into the same session ID
  HTTP.setheader(req1, "Cookie"=>ck1)
  @test Genie.Cookies.get(req1, "__geniesid"; encrypted=true)==sid1

  # STEP 2: Replay the same cookie → same session ID
  req2, res2=HTTP.Request("GET", "/"), HTTP.Response()
  HTTP.setheader(req2, "Cookie"=>ck1)
  req2, res2, params2, sess2=GenieSession.start!(req2, res2)
  @test sess2.id==sid1

  # STEP 3: Tamper with the hex blob → must yield a new session ID
  blob=match(r"__geniesid=([^;]+)", ck1).captures[1]
  lastch=blob[end]
  flipped=blob[1:end-1]*(lastch=='0' ? '1' : '0')
  bad_ck="__geniesid=$(flipped);"*split(ck1, ';', limit=2)[2]

  req3, res3=HTTP.Request("GET", "/"), HTTP.Response()
  HTTP.setheader(req3, "Cookie"=>bad_ck)
  req3, res3, params3, sess3=GenieSession.start!(req3, res3)

  @test sess3.id!=sid1          # new session created
  ck3=parse_setcookie(res3)
  @test ck3!=bad_ck             # cookie refreshed
end
