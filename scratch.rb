#!/usr/bin/env ruby

require 'net/http'
require 'rexml/document'
require 'rexml/xpath'

REXML::Security.entity_expansion_limit = 0

uri = URI.parse('https://www.signin.service.gov.uk/SAML2/metadata/federation')
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = true
request = Net::HTTP::Get.new(uri.request_uri)
response = http.request(request)

document = REXML::Document.new(response.body)

REXML::XPath.each(document, './/*[local-name(.)="EntityDescriptor"]') do |entity|
  puts 'entityID ' + entity.attribute('entityID').value

  REXML::XPath.each(entity, './/*[local-name(.)="KeyDescriptor"]') do |keyDescriptor|
    puts 'use ' + keyDescriptor.attribute('use').value
    REXML::XPath.each(keyDescriptor, './/*[local-name(.)="KeyInfo"]') do |keyInfo|
      REXML::XPath.each(keyInfo, './/*[local-name(.)="KeyName"]') do |keyName|
        puts 'keyName ' + keyName.text
      end
      REXML::XPath.each(keyInfo, './/*[local-name(.)="X509Certificate"]') do |x509|
        certText = <<~EOF
        -----BEGIN CERTIFICATE-----
        #{x509.text.gsub(/\s+/, '').gsub(/(.{1,64})/, "\\1\n").strip}
        -----END CERTIFICATE-----
        EOF
        cert = OpenSSL::X509::Certificate.new(certText)
        puts 'subject ' + cert.subject.to_s
        puts 'expires ' + cert.not_after.to_s
      end
    end
    puts ''
  end
  puts ''
end
