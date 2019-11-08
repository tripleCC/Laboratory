#!/usr/bin/env ruby

require 'set'

# Contents of (__DATA,__objc_classlist) section
# 00000001091cbad0  09dc7648 00000001 09dc7698 00000001 

class VOOtoolOutputParser
  class OClass
    attr_accessor :superclass
    attr_reader :name
    attr_reader :address

    def initialize(address, name)
      @name = name
      @address = address
    end

    def is_pod_special?
      @name.include?('PodsDummy_') 
    end

    def real_name
      @name.sub('_OBJC_CLASS_$_', '')
    end

    def ==(other)
      self.class === other and
        other.name == @name and
        other.address == @address
    end

    alias eql? ==

    def hash
      @name.hash ^ @address.hash
    end
  end

  attr_reader :class_list
  attr_reader :class_refs

  def initialize(output) 
    @output = output
  end

  def parse
    section = nil
    @class_list = []
    @class_refs = []

    @output.each do |line|
      if line.start_with?('Contents')
        section = line.match(/Contents of \(__DATA,(.*)\) section/)[1]
      else
        case section
        when '__objc_classlist'
          if line[0] == '0'
            cls = OClass.new(*line.split(' ')[1, 2])
            class_list << cls
          elsif line.strip.start_with?('superclass')
            cls = OClass.new(*line.split(' ')[1, 2])
            class_list.last.superclass = cls
          end
        when '__objc_classrefs'
          cls = OClass.new(*line.split(' ')[1, 2])
          class_refs << cls
        end
      end
    end
  end
end

class UnuseClassesFinder
  attr_reader :parser

  def initialize(bin) 
    @bin = bin
    @parser = VOOtoolOutputParser.new(otool_vo)    
    @parser.parse
  end

  def all_may_unuse_class_names
    # 父类也需要从无用数组中排除
    may_unused_classes = parser.class_list - all_superclass - parser.class_refs
    may_unused_classes = may_unused_classes.reject(&:is_pod_special?)
    may_unused_class_names = may_unused_classes.map(&:real_name).uniq

    # 过滤可能通过字符串反射的类
    may_unused_class_name_set = Set.new(may_unused_class_names)
    may_reflect_class_names = c_strings.select { |s| may_unused_class_name_set.include?(s) }
    may_unused_class_names = may_unused_class_names - may_reflect_class_names
    may_unused_class_names
  end

  private

  def c_strings
    c_string_lines = `otool #{@bin} -v  -s __RODATA __cstring`.split("\n")
    # __cstring  本来在 __TEXT ，通过 -Wl,-rename_section,__TEXT,__cstring,__RODATA,__cstring 挪到 __RODATA 了
    # iOS8 60M 限制
    c_string_lines = `otool #{@bin} -v  -s __TEXT __cstring`.split("\n") if c_string_lines.count <= 1
    c_strings = c_string_lines.map { |line| line.split(' ').last } 
    c_strings
  end

  def all_superclass
    parser.class_list.map(&:superclass).uniq
  end

  def otool_vo
    `otool -v -o #{@bin}`.split("\n")
  end
end