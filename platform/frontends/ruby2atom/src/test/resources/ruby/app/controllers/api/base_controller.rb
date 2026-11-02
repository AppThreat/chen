class Api::BaseController < ApplicationController
  include Api::RateLimitHeaders

  def index
    @form = Form::AccountBatch.new
    render json: @form, serializer: REST::AccountSerializer
    ActivityPub::TagManager.instance.uri_for(@form)
    Faraday::Utils.escape("x")
  end
end
