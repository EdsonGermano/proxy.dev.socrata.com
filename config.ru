require "rubygems"
require "bundler/setup"
require "sinatra"
require "soda/client"
require "soda/exceptions"
require "securerandom"
require "net/http"
require "sinatra/cookies"
require "sinatra/cross_origin"

require "omniauth-socrata"

require './cache.rb'

class DevProxy < Sinatra::Base
  enable :sessions
  set :session_secret, 'super duper secret'

  # CORS
  register Sinatra::CrossOrigin
  enable :cross_origin
  set :allow_origin, ENV['CORS_ORIGIN']
  set :allow_methods, [:get, :options]
  set :allow_credentials, true

  # Handle preflight requests for CORS
  options "*" do
    response.headers["Allow"] = "GET,OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = true
    response.headers["Access-Control-Allow-Origin"] = ENV['CORS_ORIGIN']
    200
  end

  get '/' do
    redirect to('/auth/socrata')
  end

  get "/logout" do
    session.clear # Bye bye auth
    redirect to("http://dev.socrata.com")
  end

  # Authenticated proxy for SODA requests
  get "/socrata/:domain/*" do
    # Security checks
    if !session[:socrata_auth]
      halt 403, "You have not authenticated with the proxy"
    elsif session[:domain] != params["domain"]
      halt 403, "You have not authenticated for domain #{params["domain"]}"
    end

    client = SODA::Client.new({
      :domain => params["domain"],
      :access_token => session[:socrata_auth].credentials.token,
      :app_token => ENV["SOCRATA_APP_TOKEN"]
    })

    begin
      response = client.get(
        "/" + params["splat"].first,
        params.reject { |k, v| ['splat', 'domain', 'captures'].include?(k) }
      )

      # Proxy our results
      return [
        200,
        {
          "Content-Type" => "application/json",
          "X-Socrata-Proxy" => request.host
        },
        response.to_json
      ]
    rescue SODA::Exception => e
      puts "SODA::Exception: #{e.inspect}"

      # Pass it on!
      return [
        e.http_code, 
        {
          "Content-Type" => "application/json",
          "X-Socrata-Proxy" => request.host
        },
        e.http_body
      ]
    rescue RuntimeError
      puts "Internal Error: #{e.inspect}"

      halt 500, "Internal Server Error"
    end
  end

  ###
  # OmniAuth Setup for Socrata
  ###
  use OmniAuth::Builder do
    provider :socrata, ENV["SOCRATA_APP_TOKEN"], ENV["SOCRATA_SECRET_TOKEN"],
      :setup => lambda { |env|
        root = "https://" + env['rack.session']['domain']
        env['omniauth.strategy'].options[:client_options].site = root
        env['omniauth.strategy'].options[:client_options].authorize_url = root + "/oauth/authorize"
      }
  end
  OmniAuth.config.full_host = ENV["SITE_ROOT"]

  get '/login/:domain/:uid' do
    # Stash it in the Sinatra session
    session.clear
    session[:domain] = params["domain"]
    session[:uid] = params["uid"]

    # Also stash it in the Rack session, for our middleware
    env['rack.session']['domain'] = params[:domain]
    redirect to("/auth/socrata")
  end

  get '/auth/socrata/callback' do
    auth = request.env['omniauth.auth']
    session[:socrata_auth] = auth

    redirect to("https://#{request.host.gsub(/^proxy\./, '')}/foundry/#/#{session[:domain]}/#{session[:uid]}/proxy")
  end

  get '/auth/failure' do
    session.clear
    "You lose!"
  end

  ########################################################################
  # Github proxy that adds in secrets to get more requests. Also, caching.
  ########################################################################
  get "/github/*" do
    response = Cache.instance.get("github|#{request.path}")
    cached = true
    if response.nil?
      puts "Fetching #{request.path} from Github..."
      uri = URI::HTTPS.build(
        :host => "api.github.com",
        :path => request.path.gsub(%r{^/github}, ""),
        :query => [request.query_string,
                   "client_id=#{ENV["GITHUB_CLIENT_ID"]}",
                   "client_secret=#{ENV["GITHUB_CLIENT_SECRET"]}"].join("&")
      )

      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_PEER

      response = http.get(uri.request_uri)
      Cache.instance.set("github|#{request.path}", response)
      cached = false
    end

    cache_control :public
    status response.code
    headers \
      "Access-Control-Allow-Origin" => request.base_url.gsub(%r{/proxy\.}, "/"),
      "Content-Type" => "application/json",
      "X-Proxy-Cached" => cached.to_s
    body response.body
  end

  def error_page(title, body='')
    "<html>" +
      "<head><title>#{title}</title></head>" +
      "<body><h1>#{title}</h1>#{body}</body>" +
      "</html>"
  end
end

run DevProxy
