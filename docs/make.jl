using Documenter

push!(LOAD_PATH,  "../../src")

using GenieSession

makedocs(
    sitename = "GenieSession - Sessions and Flash support for Genie",
    format = Documenter.HTML(prettyurls = false),
    pages = [
        "Home" => "index.md",
        "GenieSession API" => [
          "Flash" => "api/flash.md",
          "GenieSession" => "api/geniesession.md",
        ]
    ],
)

deploydocs(
  repo = "github.com/GenieFramework/GenieSession.jl.git",
)
