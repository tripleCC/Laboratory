require_relative './unuse_classes_finder'
require_relative './link_map_parser'

bin = ARGV[0] || '/Users/songruiwang/Develop/Analyze/Ipa/exe/all_static_link/com_kwai_gif'

# 输出使用的 SEL 信息（这里的信息是没带类信息的，也就是无法知道使用的是哪个类的方法，只知道了有类使用了这个 SEL）
sel_refs = `otool -v -s __DATA __objc_selrefs #{bin}`.split("\n")#[0, 5]
sel_strs = sel_refs.map { |ref| ref.split(':', 3).last }
sel_str_set = Set.new(sel_strs)

# 注意代理方法也会被过滤，实际不是无用方法
parser = LinkMap::Parser.new(Pathname.new('/Users/songruiwang/Develop/Analyze/Ipa/exe/all_static_link/com_kwai_gif-LinkMap-normal-arm64.txt'))
parser.parse
oc_method_symbols = parser.result.symbols.select(&:oc_method?).reject { |sym| sym.class_name.end_with?('Delegate') || sym.class_name.end_with?('Protocol') }

oc_method_symbols = oc_method_symbols.reject do |sym| 
  sel_str_set.include?(sym.method_name) ||
  sym.method_name == '.cxx_destruct' 
end

puts oc_method_symbols.select { |sym| 
  sym.class_name.include?('Controller') ||
  sym.class_name.include?('Component') ||
  sym.class_name.include?('View') ||
  sym.class_name.include?('Cell')
}.sort_by(&:size).reverse.take(200)
puts oc_method_symbols.count

return

finder = UnuseClassesFinder.new(bin)
puts finder.all_may_unuse_class_names

