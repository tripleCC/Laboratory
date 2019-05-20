require 'rest_client'
require 'redcarpet'
require 'parallel'
require 'nokogiri'

readme = File.open('./README.md')
markdown = Markdown.new(readme.read)
html = markdown.to_html
doc = Nokogiri::HTML(html)
links = doc.search('a').map { |link| link }
invalid_links = []
Parallel.each(links, in_threads: 10) do |link|
  url = link.attributes['href'].value
  begin
    RestClient.head(url)
  rescue RestClient::ResourceNotFound
    invalid_links << link
  end
end

if invalid_links.any?
  puts '无效链接：'
  puts '============================'
  invalid_links.each { |link| puts link.content }
  puts '============================'

  raise '需移除如上无效链接'
end
