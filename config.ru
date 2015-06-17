require "rubygems"
require "bundler/setup"
require "sinatra"
require "soda/client"
require "securerandom"
require "net/http"

require "omniauth-socrata"

require './cache.rb'

class DevProxy < Sinatra::Base
  enable :sessions
  set :session_secret, 'super duper secret'

  get '/' do
    "session: #{session.inspect}"
  end

  get "/logout" do
    session = {} # Bye bye auth
    redirect "/"
  end

  # Github proxy that adds in secrets to get more requests. Also, caching.
  get "/github/*" do
    response = Cache.instance.get("github|#{request.path}")
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
    end

    cache_control :public
    status response.code
    headers \
      "Access-Control-Allow-Origin" => request.base_url.gsub(%r{/proxy\.}, "/"),
      "Content-Type" => "application/json"
    body response.body
  end

  ###
  # OmniAuth Setup for Socrata
  ###
  use OmniAuth::Builder do
    provider :socrata, ENV["SOCRATA_APP_TOKEN"], ENV["SOCRATA_SECRET_TOKEN"]
  end
  OmniAuth.config.full_host = ENV["SITE_ROOT"]

  get '/auth/:name/callback' do
    auth = request.env['omniauth.auth']
    session[:socrata_auth] = auth
  end

  ### Helper Functions
  def client
    SODA::Client.new(:domain => ENV["DESTINATION_DOMAIN"], :app_token => ENV["SOCRATA_APP_TOKEN"], :auth => session[:socrata_auth])
  end

  def error_page(title, body='')
    "<html>" +
      "<head><title>#{title}</title></head>" +
      "<body><h1>#{title}</h1>#{body}</body>" +
      "</html>"
  end
end

run DevProxy
