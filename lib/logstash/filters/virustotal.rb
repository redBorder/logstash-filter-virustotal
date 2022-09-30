# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require 'json'
require 'faraday'
require 'rest-client'
require 'digest'
require 'aerospike'

require_relative "util/aerospike_config"
require_relative "util/aerospike_manager"

class LogStash::Filters::Virustotal < LogStash::Filters::Base

  include Aerospike

  config_name "virustotal"

  # Virustotal apikey. Please visit https://www.virustotal.com/ to get your apikey.
  config :apikey,      :validate => :string,  :default => "",  :required => true
  # File that is going to be analyzed
  config :file_field,   :validate => :string,  :default => "[path]"
  # Timeout waiting for response
  config :timeout, :validate => :number, :default => 15
  # Where you want the data to be placed
  config :target, :validate => :string, :default => "virustotal"
  # Where you want the score to be placed
  config :score_name, :validate => :string, :default => "fb_virustotal"
  # Where you want the latency to be placed
  config :latency_name, :validate => :string, :default => "virustotal_latency"
  #Aerospike server in the form "host:port"
  config :aerospike_server,                 :validate => :string,           :default => ""
  #Namespace is a Database name in Aerospike
  config :aerospike_namespace,              :validate => :string,           :default => "malware"
  #Set in Aerospike is similar to table in a relational database.
  # Where are scores stored
  config :aerospike_set,                    :validate => :string,           :default => "hashScores"


  public
  def register
    # Add instance variables
    @url = "https://www.virustotal.com/api/v3/files"

    begin
      @aerospike_server = AerospikeConfig::servers if @aerospike_server.empty?
      @aerospike_server = @aerospike_server[0] if @aerospike_server.class.to_s == "Array"
      host,port = @aerospike_server.split(":")
      @aerospike = Client.new(Host.new(host, port))

    rescue Aerospike::Exceptions::Aerospike => ex
      @logger.error(ex.message)
    end
  end # def register

  private

  # Returns response message from a given response code
  def check_response(response_code)

    case response_code
      when 400
        response_message = "CODE 400 Bad Request - Unsupported HTTP method or invalid HTTP request (e.g., empty body)"
      when 401
        response_message = "CODE 401 Invalid API key - Either missing API key or invalid API is passed."
      when 404
        response_message = "CODE 404 The requested page was not found. Try to upload the file."
      when 429
      response_message = "CODE 429 Signature lookup limit reached, try again later - The hourly hash lookup limit has been reached for this API key."
      when 503
        response_message = "CODE 503 Internal Server Error - Server temporarily unavailable. Try again later."
      else #when 200
      response_message = ""
    end

    response_message
  end

  # Get a JSON with the response from Virustotal and a score from a Hash.
  # If the hash is not in Virustotal, returns an empty JSON and score -1.
  def get_response_from_hash
    connection = Faraday.new @url + "/"
    score = -1
    result = {}

    begin
      response = connection.get @hash do |req|
        req.headers["x-apikey"] = @apikey
        req.options.timeout = @timeout
        req.options.open_timeout = @timeout
      end

      response_code = response.status
      result = JSON.parse(response.body)

      if response_code != 200
        response_message = check_response(response_code)
        @logger.error(response_message)
        return [result, score]
      end


      last_analysis_stats = result["data"]["attributes"]["last_analysis_stats"]
      total_avs = 0.0
      total_detected_avs = 0.0

      last_analysis_stats.each do |k,v|
        total_avs += v
        total_detected_avs = v if k == 'malicious'
      end

      score = ( total_detected_avs / total_avs * 100 ).round

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Virustotal")

    rescue Faraday::ConnectionFailed => ex
      @logger.error(ex.message)
    end
    [result, score]
  end

  # Send file to be analyzed by Virustotal. It returns a String with the analysis ID.
  def send_file
    data_id = nil
    response_code_error = nil

    begin
      file_name = ::File.basename(@path)
      file =      ::File.open(@path, 'r')
      options = {filename: file_name, file: file}
    rescue Errno::ENOENT=> ex
      @logger.error(ex.message)
      return data_id
    rescue Errno::EACCES=> ex
      @logger.error(ex.message)
      return data_id
    end

    # If file is bigger than 32MB, default url will not work
    # File.size(@path) returns file size in bytes
    # 1 MB are 1048576 bytes, so:
    if File.size(@path) > 32 * 1048576
      url = get_url_large_files
      return data_id if url.nil?
    else
      url = @url
    end

    begin
      response = RestClient::Request.execute(
        method: "post",
        url: url,
        headers: { 'x-apikey' => @apikey },
        timeout: @timeout,
        payload: options
      )
    rescue RestClient::Exceptions::ReadTimeout
      @logger.error("Timeout trying to contact Virustotal")
      return data_id
    rescue RestClient::Exception => ex
      response_code_error = ex.http_code
    end

    if response_code_error
      response_message = check_response(response_code_error)
      @logger.error(response_message)
      return data_id
    end

    JSON.parse(response.body)["data"]["id"]

  end

  # Get a URL for uploading files larger than 32MB
  def get_url_large_files
    upload_url = "https://www.virustotal.com/api/v3/files/upload_url"
    url = nil
    begin
      connection = Faraday.new upload_url
      response = connection.get do |req|
        req.headers["x-apikey"] = @apikey
        req.options.timeout = @timeout
        req.options.open_timeout = @timeout
      end

      url = JSON.parse(response.body)["data"]

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Virustotal")
    rescue Faraday::ConnectionFailed => ex
      @logger.error(ex.message)
    end

    url
  end

  # Get a JSON with the response from Virustotal and a score from an analysis ID.
  def get_response_from_analysis_id(data_id)
    url = "https://www.virustotal.com/api/v3/analyses/"
    connection = Faraday.new url
    progress_status = "queued"
    score = -1
    result = {}
    begin
      max_number_petitions = 100
      petitions = 0
      while progress_status != "completed" and petitions < max_number_petitions
        response = connection.get data_id do |req|
          req.headers["x-apikey"] = @apikey
          req.options.timeout = @timeout
          req.options.open_timeout = @timeout
        end
        response_code = response.status
        response_message = check_response(response_code)
        if response_code != 200
          @logger.error(response_message)
          return [score,result]
        end

        result = JSON.parse(response.body)
        progress_status = result["data"]["attributes"]["status"]
        petititons = petitions + 1
        sleep 10
      end

    rescue Faraday::TimeoutError
      @logger.error("Timeout trying to contact Virustotal")
    rescue Faraday::ConnectionFailed => ex
      @logger.error(ex.message)
    end
    
    if progress_status == "completed"
      analysis_stats = result["data"]["attributes"]["stats"]
      total_avs = 0.0
      total_detected_avs = 0.0

      analysis_stats.each do |k,v|
        total_avs += v
        total_detected_avs = v if k == 'malicious'
      end

      score = ( total_detected_avs / total_avs * 100 ).round
    end

    [result, score]
  end


  public
  def filter(event)
    @path = event.get(@file_field)
    puts "[virustotal] processing #{@path}"
    begin
      @hash = Digest::SHA2.new(256).hexdigest File.read @path
    rescue Errno::ENOENT => ex
      @logger.error(ex.message)
    end


    starting_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    virustotal_result,score = get_response_from_hash

    if virustotal_result["error"] and virustotal_result["error"]["code"] != "QuotaExceededError"
        data_id = send_file
        virustotal_result,score = get_response_from_analysis_id(data_id)
    end

    ending_time  = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    elapsed_time = (ending_time - starting_time).round(1)

    event.set(@latency_name, elapsed_time)
    event.set(@target, virustotal_result)
    event.set(@score_name, score)

    AerospikeManager::update_malware_hash_score(@aerospike, @aerospike_namespace, @aerospike_set, @hash, @score_name, score, "fb")

    # filter_matched should go in the last line of our successful code
    filter_matched(event)

  end  # def filter(event)
end # class LogStash::Filters::Metascan
