using SafeTestsets

@safetestset "Sessions Suite" begin
  using Dates, HTTP
  using Genie, Genie.Router, Genie.Secrets
  using GenieSession
  using GenieSessionFileSession
  using Genie.Cookies

  Genie.Secrets.secret_token!(repeat('0',64))   # 32 bytes → 64 hex chars
  tmpdir=mktempdir()
  GenieSessionFileSession.sessions_path(tmpdir)

  @testset "Disk‐backed sessions (encrypt, decrypt, expiry)" begin
    # 1) Create, set a value, persist
    sid1=GenieSession.id()
    sess1=Session(sid1)
    GenieSession.set!(sess1, :foo, "ZAP")
    GenieSessionFileSession.write(sess1)

    # 2) File on disk is hex & has no plaintext
    f1=joinpath(tmpdir, sid1)
    @test isfile(f1)
    raw1=read(f1, String)
    @test ! occursin("ZAP", raw1)
    @test match(r"^[0-9a-f]+$", raw1)!==nothing

    # 3) Loading recovers the data
    loaded1=GenieSession.load(sid1)
    @test isa(loaded1, Session)
    @test loaded1.id==sid1
    @test GenieSession.get(loaded1, :foo, "")=="ZAP"

    # 4) Tamper → blob invalid → empty session
    open(f1, "w") do io
      write(io, "deadbeef")
    end
    bad1=GenieSession.load(sid1)
    @test isa(bad1, Session)
    @test bad1.id==sid1
    @test isempty(bad1.data)

    # 5) Force-expire then load → empty session
    sid2=GenieSession.id()
    sess2=Session(sid2)
    GenieSession.set!(sess2, :bar, "WOW")
    # backdate it
    sess2.expires_at=Dates.now()-Minute(1)
    GenieSessionFileSession.write(sess2)
    # file still there
    f2=joinpath(tmpdir, sid2)
    @test isfile(f2)
    # but load sees expiry → empty
    expired=GenieSession.load(sid2)
    @test isa(expired, Session)
    @test expired.id==sid2
    @test isempty(expired.data)
  end

  @testset "HTTP Sessions integration (store, replay, expire & rotate)" begin
    # Define two routes: "/" stores foo="BAR", "/check" reads it
    route("/") do
      s=session(params())
      GenieSession.set!(s, :foo, "BAR")
      "stored"
    end

    route("/check") do
      s=session(params())
      GenieSession.get(s, :foo, "MISSING")
    end

    # Start the server synchronously
    HOST="127.0.0.1"
    PORT=rand(20000:30000)
    @async up(PORT, HOST; async=false, open_browser=false)
    sleep(0.1)  # give it a moment to bind

    # 1) First GET → sets cookie, returns "stored"
    r1=HTTP.get("http://$HOST:$PORT/")
    @test r1.status==200
    @test String(r1.body)=="stored"

    # 2) Extract the __geniesid cookie (full Set-Cookie header)
    setcookie1=Dict(r1.headers)["Set-Cookie"]
    cookie_kv1=split(setcookie1, ";", limit=2)[1]  # "__geniesid=…"

    # 3) Use Cookies API to recover the (decrypted) session ID
    req1b=HTTP.Request("GET", "/")
    HTTP.setheader(req1b, "Cookie"=>cookie_kv1)
    sid1=Genie.Cookies.get(req1b, "__geniesid"; encrypted=true)
    @test length(sid1)==64

    # 4) Replay the _encrypted_ cookie blob (not raw SID) → returns "BAR"
    r2=HTTP.get(
      "http://$HOST:$PORT/check";
      headers=Dict("Cookie"=>cookie_kv1)
    )
    @test r2.status==200
    @test String(r2.body)=="BAR"

    # 5) Use sid1 as raw SID for disk work
    raw_sid=sid1
    @test length(raw_sid)==64

    # 6) Force‐expire that on‐disk session
    sess3=GenieSessionFileSession.read(raw_sid)
    @test sess3 isa Session
    sess3.expires_at=Dates.now()-Minute(1)
    GenieSessionFileSession.write(sess3)

    # 7) Replay the same _encrypted_ cookie again → returns "MISSING"
    r3=HTTP.get(
      "http://$HOST:$PORT/check";
      headers=Dict("Cookie"=>cookie_kv1)
    )
    @test String(r3.body)=="MISSING"

    # Cookie is still accepted and maps to the same, now-empty session
    req3b=HTTP.Request("GET", "/")
    HTTP.setheader(req3b, "Cookie"=>cookie_kv1)
    sid_after=Genie.Cookies.get(req3b, "__geniesid"; encrypted=true)
    @test sid_after==raw_sid

    # Tear down
    down()
    rm(tmpdir; force=true, recursive=true)
  end

  @testset "rotate! session‐ID rotation" begin
    # Step A: fix secret & temp folder
    Genie.Secrets.secret_token!(repeat('0',64))
    tmpdir=mktempdir()
    GenieSessionFileSession.sessions_path(tmpdir)

    # Step B: create & persist initial session
    sid0=GenieSession.id()
    s0=Session(sid0)
    GenieSession.set!(s0, :answer, 42)
    GenieSessionFileSession.write(s0)
    @test isfile(joinpath(tmpdir, sid0))

    # Step C: simulate HTTP req/res
    req=HTTP.Request("GET", "/dummy")
    res=HTTP.Response()

    # Step D: rotate!
    s1=GenieSession.rotate!(s0, req, res; options=GenieSession.session_options())

    # Step E: verify semantics
    @test s1.id!=sid0
    @test GenieSession.get(s1, :answer)==42
    # We only require that the new file exists; core rotate! does not delete old file.
    @test isfile(joinpath(tmpdir, s1.id))

    # Step F: check Set-Cookie
    sc=HTTP.header(res, "Set-Cookie")
    @test ! isempty(sc)
    cookie_kv=split(sc, ";", limit=2)[1]
    req_cookie=HTTP.Request("GET", "/dummy")
    HTTP.setheader(req_cookie, "Cookie"=>cookie_kv)
    sid_from_cookie=Genie.Cookies.get(req_cookie, "__geniesid"; encrypted=true)
    @test sid_from_cookie==s1.id
    @test sid_from_cookie!=sid0

    # cleanup
    rm(tmpdir; force=true, recursive=true)
  end
  @testset "rotate_file_session! deletes old file" begin
    # Step A: fix secret & temp folder
    Genie.Secrets.secret_token!(repeat('0',64))
    tmpdir=mktempdir()
    GenieSessionFileSession.sessions_path(tmpdir)

    # Step B: create & persist initial session
    sid0=GenieSession.id()
    s0=Session(sid0)
    GenieSession.set!(s0, :answer, 42)
    GenieSessionFileSession.write(s0)
    @test isfile(joinpath(tmpdir, sid0))

    # Step C: simulate HTTP req/res
    req=HTTP.Request("GET", "/dummy")
    res=HTTP.Response()

    # Step D: rotate via file-session helper
    s1=GenieSessionFileSession.rotate_file_session!(s0, req, res; options=GenieSession.session_options())

    # Step E: verify semantics
    @test s1.id!=sid0
    @test GenieSession.get(s1, :answer)==42
    @test ! isfile(joinpath(tmpdir, sid0))          # old file removed
    @test isfile(joinpath(tmpdir, s1.id))           # new file exists

    # Step F: check Set-Cookie corresponds to new ID
    sc=HTTP.header(res, "Set-Cookie")
    @test ! isempty(sc)
    cookie_kv=split(sc, ";", limit=2)[1]
    req_cookie=HTTP.Request("GET", "/dummy")
    HTTP.setheader(req_cookie, "Cookie"=>cookie_kv)
    sid_from_cookie=Genie.Cookies.get(req_cookie, "__geniesid"; encrypted=true)
    @test sid_from_cookie==s1.id
    @test sid_from_cookie!=sid0

    rm(tmpdir; force=true, recursive=true)
  end
end
