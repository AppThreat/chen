# Forwarded-header shapes: request accessors, header reads and the trusted-proxy setting.
class WidgetsController < ApplicationController
  def show
    remote = request.remote_ip
    client = request.ip
    host = request.host
    full_host = request.host_with_port
    base = request.base_url
    url = request.url
    proto = request.protocol
    secure = request.ssl?
    fwd = request.headers['X-Forwarded-For']
    raw_host = request.raw_host_with_port()
    direct = request.get_header('X-Real-IP')
    env_fwd = request.env['HTTP_X_FORWARDED_FOR']
    render json: { ip: remote, host: host }
  end

  # A method-call form of the same accessors (with parentheses).
  def update
    client = request.remote_ip()
    host = request.host()
    render json: { ip: client, host: host }
  end

  # Bad twins: the same names on receivers that are not the request object.
  def twins(device, config)
    device_ip = device.ip
    config_host = config.host
    remote = device.remote_ip
    render json: { ip: device_ip, host: config_host }
  end
end

module Fwd
  class Application < Rails::Application
    config.action_dispatch.trusted_proxies = %w[10.0.0.0/8]
  end
end
