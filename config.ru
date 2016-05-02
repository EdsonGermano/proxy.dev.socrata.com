require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'soda/client'
require 'soda/exceptions'
require 'securerandom'
require 'net/http'
require 'sinatra/cookies'
require 'uri'
require 'erb'
require 'active_support/inflector'

require 'omniauth-socrata'

require './cache.rb'

class DevProxy < Sinatra::Base
  # Session cookies
  enable :sessions
  set :session_secret, 'super duper secret'

  # Normal cookies
  helpers Sinatra::Cookies
  set :cookie_options, {
    :domain => ENV['DEV_SITE_DOMAIN'],
    :httponly => false
  }

  CORS_HEADERS = {
    # Only allow CORS from our dev site, and only read-only
    "Access-Control-Allow-Origin" => "https://#{ENV['DEV_SITE_DOMAIN']}",
    "Access-Control-Allow-Methods" => "OPTIONS,HEAD,GET",
    "Access-Control-Allow-Credentials" => "true",
    "Access-Control-Allow-Headers" => "*"
  }

  # Handle preflight requests for CORS
  options "*" do
    [
      200,
      CORS_HEADERS,
      nil
    ]
  end

  get '/' do
    redirect to('/auth/socrata')
  end

  get "/logout/" do
    session.clear # Bye bye auth
    cookies.clear # Bye bye shared info
    redirect to("https://#{ENV['DEV_SITE_DOMAIN']}")
  end

  # Authenticated proxy for SODA requests
  get "/socrata/:domain/*" do
    # Security checks
    access_token = if session[:socrata_auth_token] && session[:domain] == params["domain"]
      puts "Authenticating proxied request as #{session[:socrata_auth_email]}"
      session[:socrata_auth_token]
    else
      puts "Passing on request unauthenticated"
      nil
    end

    client = SODA::Client.new({
      :domain => params["domain"],
      :access_token => access_token,
      :app_token => ENV["SOCRATA_APP_TOKEN"],
      :ignore_ssl => ENV["IGNORE_SSL"] == "true"
    })

    # We share common headers for all our responses
    # TODO: I know this means we can only deal with JSON right now
    # We should really copy the output type from the API response's headers
    headers = CORS_HEADERS.merge({
      "Content-Type" => "application/json",
      "X-Socrata-Proxy" => request.host
    })

    begin
      response = client.get(
        "/" + params["splat"].first,
        params.reject { |k, v| ['splat', 'domain', 'captures'].include?(k) }
      )

      # Proxy our results
      return [
        200,
        headers,
        response.to_json
      ]
    rescue SODA::Exception => e
      puts "SODA::Exception: #{e.inspect}"

      # Pass it on!
      return [
        e.http_code,
        headers,
        e.http_body
      ]
    rescue RuntimeError => e
      puts "Internal Error: #{e.inspect}"

      return [500, headers, "Internal Server Error"]
    end
  end

  def generate_parameters(metadata, soql_json)
    # Dataset Properties
    parameters = metadata.columns
    .reject { |f| soql_json.datatypes[f.dataTypeName].definition.type == "object" }
    .collect do |f|
      {
        name: f.fieldName,
        in: :query,
        description: f.description,
        required: false
      }
      .merge(soql_json.datatypes[f.dataTypeName].definition)
      .reject { |k, v| v.nil? }
    end

    return parameters + soql_json.parameters.values
  end

  def generate_responses(metadata, soql_json, entity_name)
    return soql_json.response_codes.inject({}) do |mem, resp|
      mem[resp.first] = case resp.first
                        when "200"
                          {
                            description: "A set of #{entity_name.pluralize.capitalize} matching your query",
                            schema: {
                              type: :array,
                              items: {
                                :$ref => "#/definitions/#{entity_name.capitalize}"
                              }
                            }
                          }
                        when "202"
                          {
                            description: "Your query is in-flight and may be retried"
                          }
                        else
                          {
                            description: "#{resp.last.name}: #{resp.last.description}",
                            schema: {
                              :$ref => "#/definitions/#{resp.last.response}"
                            }
                          }
                        end
      mem
    end
  end

  def generate_definitions(metadata, soql_json, entity_name)
    return soql_json.standard_responses.merge({
      entity_name.capitalize => {
        type: :object,
        properties: metadata.columns.inject({}) { |mem, f|
          field = {
            description: f.description,
          }
          .merge(soql_json.datatypes[f.dataTypeName].definition)
          .reject { |k, v| v.nil? }


          mem[f.fieldName] = field
          mem
        }
      }
    })
  end

  # Authenticated OpenAPI spec generation
  get "/openapi/:domain/:uid" do
    # We share common headers for all our responses
    headers = CORS_HEADERS.merge({
      "Content-Type" => "application/json",
      "X-Socrata-Proxy" => request.host
    })

    # Security checks
    access_token = if session[:socrata_auth_token] && session[:domain] == params["domain"]
      puts "Authenticating openapi request as #{session[:socrata_auth_email]}"
      session[:socrata_auth_token]
    else
      # For unauthenticated requests, we allow CORS requests from other sites
      headers["Access-Control-Allow-Origin"] = "*"

      puts "Passing on request unauthenticated"
      nil
    end

    client = SODA::Client.new({
      :domain => params["domain"],
      :access_token => access_token,
      :app_token => ENV["SOCRATA_APP_TOKEN"],
      :ignore_ssl => ENV["IGNORE_SSL"] == "true"
    })

    begin
      domain = params[:domain]
      uid = params[:uid]
      metadata = client.get("https://#{domain}/api/views/#{uid}.json")
      soql_json = client.get(ENV['SOQL_JSON'])
      version = metadata.newBackend ? "2.1" : "2.0"

      begin
        # Alas, I stll need to fetch OBE metadata for datasets...
        migration = client.get("https://#{domain}/api/migrations/#{uid}.json")

        # If we're on OBE, and we've got an NBE dataset to redirect to, send them there
        if !metadata.newBackend && migration.nbeId
          puts "Redirecting to 2.1 version of this API"
          return [
            302,
            headers.merge("Location" => "#{ENV['SITE_ROOT']}/openapi/#{domain}/#{migration.nbeId}"),
            nil
          ]
        end

        obe_metadata = client.get("https://#{domain}/api/views/#{migration.obeId}.json")

        metadata = obe_metadata.merge({"columns" => metadata.columns})
      rescue SODA::Exception => e
        if !metadata.newBackend
          # Ah crap. An OBE-only dataset. Well, we have little option other than just to fail
          return [
            404,
            headers,
            "OpenAPI specifications are unavailable for filtered views and 2.0-only datasets"
          ]
        else
          puts "Caught an exception fetching migrations. Let's just swallow this and hope things work out"
          $stderr.puts e.inspect
        end
      end

      # We have to do a little column meta munging, because reasons
      metadata.columns.each do |col|
        col.dataTypeName = case col.dataTypeName
                           when "calendar_date"
                             "floating_timestamp"
                           else
                             col.dataTypeName
                           end
      end

      # Now we generate a gigantic JSON document
      entity_name = metadata.rowLabel || "record"
      formats = ["application/json"] # TODO: Other output types?

      openapi = {
        swagger: '2.0',
        info: {
          version: version,
          title: metadata.name,
          description: metadata.description,
          termsOfService: "https://www.socrata.com/terms-of-service/",
          contact: {
            name: domain
          }
        },
        host: domain,
        basePath: "/",
        schemes: [
          :https
        ],
        produces: formats,
        paths: {
          "/resource/#{uid}" => {
            get: {
              description: "Returns all #{entity_name.pluralize}",
              operationId: "query#{entity_name.pluralize.capitalize}",
              produces: formats,
              parameters: generate_parameters(metadata, soql_json),
              responses: generate_responses(metadata, soql_json, entity_name)
            }
          }
        },
        definitions: generate_definitions(metadata, soql_json, entity_name)
      }

      return [
        200,
        headers,
        JSON.pretty_generate(openapi)
      ]
    rescue SODA::Exception => e
      puts "SODA::Exception: #{e.inspect}, #{e.http_body}"
      puts e.backtrace.join ", "

      # Pass it on!
      return [
        e.http_code,
        headers,
        e.http_body
      ]
    rescue RuntimeError => e
      puts "Internal Error: #{e.inspect}"

      return [500, headers, "Internal Server Error"]
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

  get '/login/:domain' do
    # Stash it in the Sinatra session
    session[:domain] = params["domain"]
    session[:return] = params["return"]

    # Also stash it in the Rack session, for our middleware
    env['rack.session']['domain'] = params[:domain]
    # TODO: Can I pass the domain information via the redirect instead of the session?
    redirect to("/auth/socrata")
  end

  get '/auth/socrata/callback' do
    # Store our auth in a session cookie for security
    auth = request.env['omniauth.auth']
    session[:socrata_auth_token] = auth.credentials.token
    session[:socrata_auth_email] = auth.extra.raw_info.email

    cookies[:dev_proxy_domain] = session[:domain]
    cookies[:dev_proxy_user] = auth.extra.raw_info.screenName

    redirect to(session[:return])
  end

  get '/auth/failure' do
    puts "Auth Failed: " + params.inspect
    redirect to("/login/#{session[:domain]}?return=#{URI.escape(session[:return])}")
  end

  # Proxy for Athena requests to do CORS
  get '/athena/*' do
    headers = CORS_HEADERS.merge({
      "Content-Type" => "application/json",
      "X-Socrata-Proxy" => request.host
    })

    begin
      puts params['splat'].inspect
      res = Net::HTTP.get_response(URI('http://socrata-athena.herokuapp.com/' + params['splat'].first))

      return [
        res.code.to_i,
        CORS_HEADERS.merge(res.to_hash),
        res.body
      ]
    rescue RuntimeError => e
      puts "Internal Error: #{e.inspect}"

      return [500, headers, "Internal Server Error"]
    end
  end

  # Proxy for GitHub requests, to add in authentication details
  get '/github/*' do
    begin
      uri = URI('https://api.github.com/' + params['splat'].first)

      # Merge in our GitHub authentication details
      uri.query = params
        .reject { |k,v| k == "splat" }
        .merge({
          "client_id" => ENV['GITHUB_CLIENT_ID'],
          "client_secret" => ENV['GITHUB_CLIENT_SECRET']
        })
        .collect { |k,v| "#{k}=#{v}" }
        .join("&")

      puts "Passing #{uri.query.inspect} to GitHub..."
      res = Net::HTTP.get_response(uri)
      code = res.code.to_i
      # Strip out some headers that cause problems
      headers = res.to_hash.reject { |k, v|
        ["status", "transfer-encoding"].include?(k.downcase)
      }.merge(CORS_HEADERS)
      body = res.body

      return [
        code,
        headers,
        body
      ]
    rescue RuntimeError => e
      puts "Internal Error: #{e.inspect}"

      return [500, headers, "Internal Server Error"]
    end
  end

end

run DevProxy
