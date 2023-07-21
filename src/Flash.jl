"""
Various utility functions for using across models, controllers and views.
"""
module Flash

import Genie
import GenieSession
using Genie.Context

export flash, flash_has_message


"""
    flash()

Returns the `flash` data associated with the current HTTP request.
"""
function flash(params::Genie.Context.Params) :: String
  GenieSession.get(params, :flash, "")
end


"""
    flash(params::Params, value::Any) :: Nothing

Stores `value` onto the flash.
"""
function flash(params::Genie.Context.Params, value::T) :: T where T
  GenieSession.set!(params, :flash, value)
  params[:flash] = value
end


"""
    flash_has_message(params::Params) :: Bool

Checks if there's any value on the flash storage
"""
function flash_has_message(params::Params) :: Bool
  haskey(params.collection, :flash) && ! isempty(params[:flash])
end

end
