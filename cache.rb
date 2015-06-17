require 'dalli'
require 'memcachier'
require 'singleton'

# Cache Client
class Cache
  include Singleton
  TTL = 60*60*1

  def initialize
    @cache = Dalli::Client.new
  end

  def get(key)
    @cache.get(key)
  end

  def set(key, value, ttl = TTL)
    @cache.set(key, value, ttl)
  end

  def delete(key)
    @cache.delete(key)
  end
end
