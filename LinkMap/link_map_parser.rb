require 'pathname'

module LinkMap
	class Result
		PREFIX = '#'

		attr_reader :sections
		attr_reader :object_files
		attr_reader :symbols
		attr_reader :segments

		def initialize
			@sections = []
			@object_file_index_hash = {}
		end

		def segments
			@segments ||= sections.group_by(&:segment).map do |key, value|
				Segment.new(key, value)
			end.sort_by(&:size).reverse
		end

		def symbols
			@symbols ||= object_files.map(&:symbols).flatten.uniq.sort_by(&:size).reverse
		end

		def object_files
			@object_files ||= @object_file_index_hash.values.uniq.sort_by(&:size).reverse
		end

		def libraries
			@libraries ||= object_files.group_by(&:extra_name).map do |key, value|
				Library.new(key, value)
			end.sort_by(&:size).reverse
		end

		def add_section(section)
			@sections << section
		end

		def add_symbol(symbol)
			object_file = @object_file_index_hash[symbol.index]
			object_file.add_symbol(symbol)
		end

		def add_object_file(object_file)
			@object_file_index_hash[object_file.index] = object_file
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

		class Library
			attr_reader :object_files
			attr_reader :size
			attr_reader :name

			def initialize(name, object_files)
				@name = name
				@object_files = object_files || []
			end

			def add_object_file(object_files)
				@object_files << object_file
			end

			def size
				@size ||= @object_files.map(&:size).reduce(&:+)
			end

			def to_s
				"#{name} #{size}"
			end
		end

		class Segment
			attr_reader :name
			attr_reader :sections

			def initialize(name, sections)
				@name = name
				@sections = sections
			end

			def size
				@size ||= sections.map(&:size).reduce(&:+)
			end

			def to_s
				"#{name} #{size}"
			end
		end

		class ObjectFile < Base
			DECLARE = 'Object files:'

			attr_reader :index
			attr_reader :name
			attr_reader :extra_name
			attr_reader :symbols
			attr_reader :size

			def initialize(line) 
				@index = line.match(/\[\s*(\d+)\]/)[1]
				basename = File.basename(line.split(' ').last)
				match_result = basename.match(/(.*)\((.*)\)/)
				if match_result
					@extra_name, @name = match_result[1, 2] 
				else
					@extra_name = @name = basename
				end

				@symbols = []

				super line
			end 

			def size
				@size ||= @symbols.map(&:size).reduce(&:+)
			end

			def add_symbol(symbol) 
				@symbols << symbol
			end

			def to_s
				s = "#{index} #{size} #{extra_name}"
				s << "  #{name}" unless name == extra_name
				s
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
				@size = @size.hex

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

			def size
				@size.hex
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


# link_map = Pathname.new('TestException_Example-LinkMap-normal-x86_64.txt')
# # p link_map
# parser = LinkMap::Parser.new(link_map)
# parser.parse
# # puts parser.result.symbols.reject(&:is_dead?)
# # puts parser.result.sections

# puts parser.result.symbols.reject(&:is_dead?)[0, 50]
# puts parser.result.segments

# puts parser.result.object_files.first.symbols
