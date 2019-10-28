require 'pathname'

module LinkMap
	class Result
		PREFIX = '#'

		attr_reader :sections
		attr_reader :object_files
		attr_reader :symbols

		def initialize
			@sections = []
			@symbols = []
			@object_files = []
		end

		def add_section(section)
			@sections << section
		end

		def add_symbol(symbol)
			object_file = @object_files.find { |o| o.index == symbol.index }
			object_file.add_symbol(symbol)
			@symbols << symbol
		end

		def add_object_file(object_file)
			@object_files << object_file
		end

		class Base
			attr_reader :line

			def initialize(line) 
				@line = line
			end

			def self.from_line(line)
				new line
			end
		end

		class ObjectFile < Base
			DECLARE = 'Object files:'

			attr_reader :index
			attr_reader :name
			attr_reader :symbols

			def initialize(line) 
				@index = line.match(/\[\s*(\d+)\]/)[1]
				@name = File.basename(line.split(' ').last)
				@symbols = []

				super line
			end 

			def add_symbol(symbol) 
				@symbols << symbol
				@symbols.uniq
			end

			def to_s
				"#{index} #{name}"
			end
		end

		class Section < Base
			DECLARE = 'Sections:'

			attr_reader :address
			attr_reader :size
			attr_reader :segment
			attr_reader :name

			def initialize(line) 
				@address, 
				@size, 
				@segment, 
				@name = line.split(' ')

				super line
			end

			def to_s
				@line
			end
		end

		class Symbol < Base
			DECLARE = 'Symbols:'

			attr_reader :address
			attr_reader :size
			attr_reader :index
			attr_reader :name

			def initialize(line) 
				first_part, second_part = line.split('[', 2)
				@address, @size = first_part.split(' ')
				@index, @name = second_part.split(']', 2)
				@index = @index.strip

				super line
			end 

			def is_dead?
				@address == '<<dead>>' 
			end

			def to_s
				"#{address} #{size} [#{index}] #{name}"
			end
		end
	end

	class Parser

		attr_reader :result

		def initialize(file) 
			@file = file
			@result = Result.new
		end

		def parse
			lines = open(@file).read.scrub.split("\n")

			declare = nil
			lines.each do |line|
				next if line.empty?

				if line.start_with?(Result::PREFIX)
					find_result = [
					 	Result::ObjectFile::DECLARE, 
					 	Result::Section::DECLARE, 
					 	Result::Symbol::DECLARE
					 	].find { |dec| line.include?(dec) }

					declare = find_result if find_result
					next if line.start_with?(Result::PREFIX)
				end

				case declare
				when Result::ObjectFile::DECLARE
					object_file = Result::ObjectFile.from_line(line)
					result.add_object_file(object_file)
				when Result::Section::DECLARE
					section = Result::Section.from_line(line)
					result.add_section(section)
				when Result::Symbol::DECLARE
					symbol = Result::Symbol.from_line(line)
					result.add_symbol(symbol)
				end
			end
		end
	end
end


link_map = Pathname.glob('./*.txt').first
# p link_map
parser = LinkMap::Parser.new(link_map)
parser.parse
# puts parser.result.symbols.reject(&:is_dead?)
# puts parser.result.sections

puts parser.result.object_files.first
puts parser.result.object_files.first.symbols
