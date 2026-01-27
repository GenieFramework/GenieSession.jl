"""
    GenieSession

In-memory session state and session control for Genie web applications.

This module provides the primary session management API. It handles secure
session ID creation, flash messages, and accessors to per-user session
variables. Sessions are persisted under the hood by `GenieSessionFileSession`,
but this module exposes the key interface for middleware, controllers,
and utilities. The session system supports cryptographically secure IDs,
sliding and absolute expiration, and storage of arbitrary key/value pairs.

Features include:
- Secure random session ID generation via `GenieSession.id`](@ref)
- Session state managed by the `GenieSession.Session`](@ref) mutable struct
- Cookie configuration utilities: `GenieSession.session_key_name`](@ref),
  `GenieSession.session_options`](@ref)
- Session start/load/persist API: `GenieSession.start`](@ref),
  `GenieSession.persist`](@ref), `GenieSession.load`](@ref)
- Session ID rotation after login via `GenieSession.rotate!`](@ref)
- Accessor shortcuts: `GenieSession.set!`](@ref),
  `GenieSession.get`](@ref), `GenieSession.unset!`](@ref),
  `GenieSession.isset`](@ref)
- "Flash" messaging submodule: `GenieSession.Flash.flash`](@ref)
- Parameter integration for working with Genie router params:
  `GenieSession.session`](@ref)

See also:
- `GenieSessionFileSession` for disk-backed persistence.
- `Genie.Cookies`](@ref) for cookie manipulation.
- `Genie.Router`](@ref) for integration points.
- `Genie.Secrets`](@ref) for secret token management.

Persistent storage and expiration policy is delegated to the configured
session persistence adapter (see `GenieSessionFileSession`](@ref)).
"""
module GenieSession

import SHA, HTTP, Dates, Logging, Random
import Genie

export Session, session

# 1) Constants & Configuration

const PARAMS_SESSION_KEY=:SESSION
const PARAMS_FLASH_KEY=:FLASH

const SESSION_KEY_NAME=Ref{String}("__geniesid")

const SESSION_TTL=Ref{Dates.Period}(Dates.Minute(30))

"""
    session_key_name()::String

Return the current cookie name used to store the session ID.
"""
function session_key_name()::String
  SESSION_KEY_NAME[]
end

"""
    session_key_name(name::String)

Set the cookie name used to store the session ID.
"""
function session_key_name(name::String)
  SESSION_KEY_NAME[]=name
end

const SESSION_OPTIONS=Ref{Dict{String,Any}}(Dict{String,Any}())

"""
    session_options()::Dict{String,Any}

Return the default cookie-options (Path, Secure, HttpOnly, SameSite, MaxAge).
"""
function session_options()::Dict{String,Any}
  SESSION_OPTIONS[]
end

"""
    session_options(options::Dict{String,Any})

Override the default cookie-options for session cookies.
"""
function session_options(options::Dict{String,Any})
  SESSION_OPTIONS[]=options
end

# 2) Session type & constructor

"""
    mutable struct Session

Hold session state in memory.
"""
mutable struct Session
  id::String
  data::Dict{Symbol,Any}
  created_at::Dates.DateTime
  expires_at::Dates.DateTime
end

const SESSION_TTL=Ref{Dates.Period}(Dates.Minute(30))

"""
    Session(id::String)::Session

Create a new `Session` with the given `id`, empty `data` dict,
`created_at = now()`, and `expires_at = now() + SESSION_TTL[]`.
"""
function Session(id::String)
  now=Dates.now()
  exp=now+SESSION_TTL[]
  Session(id, Dict{Symbol,Any}(), now, exp)
end

# 3) Exceptions & CSPRNG

struct InvalidSessionIdException <: Exception
  msg::String
end

InvalidSessionIdException()=
  InvalidSessionIdException(
    "Can't compute session id - make sure that secret_token!(token)
    is called in config/secrets.jl"
  )

const CSPRNG=Random.RandomDevice()

include("Flash.jl")

# 5) Session ID utilities

"""
    id()::String

Generate a new, cryptographically secure session ID.
Throws if no secrets token is set in production.
"""
function id()::String
  if isempty(Genie.Secrets.secret_token())
    if ! Genie.Configuration.isprod()
      @debug "Empty Genie.Secrets.secret_token(); using a temporary token"
      Genie.Secrets.secret_token!()
    else
      throw(InvalidSessionIdException())
    end
  end

  bytes2hex(
    SHA.sha256(
      Genie.Secrets.secret_token()*
      string(rand(GenieSession.CSPRNG, UInt128))
    )
  )
end

"""
    id(payload::HTTP.Request|HTTP.Response)::String

Get the session ID from the cookies of the request/response.
If missing or empty, generate a new ID via `id()`.
"""
function id(payload::Union{HTTP.Request,HTTP.Response})::String
  (Genie.Cookies.get(payload, session_key_name())!==nothing) &&
    ! isempty(Genie.Cookies.get(payload, session_key_name())) &&
      return Genie.Cookies.get(payload, session_key_name())

  id()
end

"""
    id(req::HTTP.Request, res::HTTP.Response)::String

Check both `req` and `res` for an existing session cookie; if none,
generate a fresh session ID.
"""
function id(req::HTTP.Request, res::HTTP.Response)::String
  for r in (req, res)
    val=Genie.Cookies.get(r, session_key_name())
    (val!==nothing) && ! isempty(val) &&
      return val
  end

  id()
end

# 6) Module initializer

function __init__()::Nothing
  # Fall back to static defaults that work with existing Genie versions
  # Path: "/", HttpOnly: true, Secure: prod only, SameSite: "Lax", MaxAge: 30 days
  SESSION_OPTIONS[]=Dict{String,Any}(
    "Path"=>"/",
    "HttpOnly"=>true,
    "Secure"=>(Genie.Configuration.isprod()),
    "SameSite"=>"Lax",
    "MaxAge"=>2592000
  )

  GenieSession.start in Genie.Router.pre_match_hooks ||
    push!(Genie.Router.pre_match_hooks, GenieSession.start)
  GenieSession.persist in Genie.Router.pre_response_hooks ||
    push!(Genie.Router.pre_response_hooks, GenieSession.persist)

  nothing
end

# 7) Core start/load/persist API

"""
    start(session_id::String, req::HTTP.Request, res::HTTP.Response;
          options=session_options())::(Session,HTTP.Response)

Set the session cookie to `session_id` with given `options`, then call
`GenieSession.load(session_id)` to rebuild the session object.
"""
function start(
  session_id::String,
  req::HTTP.Request,
  res::HTTP.Response;
  options::Dict{String,Any}=session_options())::Tuple{Session,HTTP.Response}
  Genie.Cookies.set!(res, session_key_name(), session_id, options, encrypted=true)

  load(session_id), res
end

"""
    start(req::HTTP.Request, res::HTTP.Response, params;
          options=session_options())::(req, res, params, Session)

Hook to bind a session into `params`. Will call the three-arg `start(id(),…)`
to get `(session,res)`, then store `params[:SESSION] = session` and
`params[:FLASH]` from prior request.
"""
function start(
  req::HTTP.Request,
  res::HTTP.Response,
  params::Dict{Symbol,Any}=Dict{Symbol,Any}();
  options::Dict{String,Any}=session_options()
  )::Tuple{HTTP.Request,HTTP.Response,Dict{Symbol,Any},Session}
  session, res=start(id(req, res), req, res; options=options)

  params[PARAMS_SESSION_KEY]=session
  params[PARAMS_FLASH_KEY]=begin
    if session!==nothing
      s=get(session, PARAMS_FLASH_KEY)
      if s===nothing
        ""
      else
        unset!(session, PARAMS_FLASH_KEY)
        s
      end
    else
      ""
    end
  end

  req, res, params, session
end

const start! = start

"""
    persist(s::Session)::Session

Persist an in-memory session `s` by delegating to the underlying adapter
(for example `GenieSessionFileSession.write(s)`).
"""
function persist end

"""
    load(session_id::String)::Session

Load or create a session object by delegating to the underlying adapter
(for example `GenieSessionFileSession.read(session_id)`).
"""
function load end

"""
    rotate!(sess::Session, req::HTTP.Request, res::HTTP.Response;
            options=session_options())::Session

Generate a fresh session ID, carry over all `sess.data`, update the session
timestamps, set the new cookie on `res`, and persist the new session.

Use this after a successful login to prevent session fixation. Storage backends
(such as `GenieSessionFileSession`) may optionally provide helpers that also
delete the old stored session data on disk.
"""
function rotate!(
  sess::Session,
  req::HTTP.Request,
  res::HTTP.Response;
  options::Dict{String,Any}=session_options())::Session
  oldid=sess.id
  newid=id()

  sess.id=newid
  sess.created_at=Dates.now()
  sess.expires_at=Dates.now()+SESSION_TTL[]

  Genie.Cookies.set!(res, session_key_name(), newid, options, encrypted=true)

  persist(sess)  # let adapter handle storage
end

# 8) Convenience accessors

"""
    set!(s::Session, key::Symbol, value)::Session

Store `value` under `key` in session `s`, persist it to disk, and return `s`.
"""
function set!(s::Session, key::Symbol, value::Any)::Session
  s.data[key]=value
  persist(s)
end

"""
    set!(key::Symbol, value)::Session

Shorthand `set!(session(), key, value)`.
"""
function set!(key::Symbol, value::Any)::Session
  set!(session(), key, value)
end

"""
    get(s::Session, key::Symbol)::Union{Any, Nothing}

Return the value `s.data[key]` if present, otherwise `nothing`.
"""
function get(s::Session, key::Symbol)::Union{Nothing,Any}
  haskey(s.data, key) ? s.data[key] : nothing
end

function get(key::Symbol)::Union{Nothing,Any}
  get(session(), key)
end

"""
    get()::Dict{Symbol,Any}

Return the entire `session().data` dictionary.
"""
function get()::Dict{Symbol,Any}
  session().data
end

"""
    get(s::Session, key::Symbol, default::T)::T where T

Attempt to retrieve the value stored on the `Session` object `s` as `key`.
If the value is not set, it returns the `default`.
"""
function get(s::Session, key::Symbol, default::T) where T
  val=get(s, key)
  val===nothing ? default : val
end

function get(key::Symbol, default::T) where T
  get(session(), key, default)
end

function get!(key::Symbol, default::T) where T
  get!(session(), key, default)
end

function get!(s::Session, key::Symbol, default::T) where T
  val=get(s, key, default)
  set!(key, val)
  val
end

"""
    unset!(s::Session, key::Symbol)::Session

Remove `key` from `s.data` and return `s`.
"""
function unset!(s::Session, key::Symbol)::Session
  delete!(s.data, key)
  s
end

"""
    isset(s::Session, key::Symbol)::Bool

Return `true` if `key` exists in `s.data`.
"""
function isset(s::Union{Session,Nothing}, key::Symbol)::Bool
  s!==nothing && haskey(s.data, key)
end

# 9) session(params) helper

"""
    session(params)::Session

Return the `Session` stored in `params[:SESSION]`. If missing,
invoke `start!` to ensure one exists.
"""
function session(params::Dict{Symbol,Any}=Genie.Router.params())::Session
  ((! haskey(params, PARAMS_SESSION_KEY) || isnothing(params[PARAMS_SESSION_KEY]))) &&
    (params=GenieSession.start!(
      Base.get(params, Genie.Router.PARAMS_REQUEST_KEY, HTTP.Request()),
      Base.get(params, Genie.Router.PARAMS_RESPONSE_KEY, HTTP.Response())
    )[3])

  params[PARAMS_SESSION_KEY]
end

end
