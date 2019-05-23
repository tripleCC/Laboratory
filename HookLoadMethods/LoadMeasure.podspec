#
# Be sure to run `pod lib lint OCHooking.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'LoadMeasure'
  s.version          = '0.1.0'

  s.summary          = 'measure load time consumption.'

  s.description      = <<-DESC
LoadMeasure measure load time consumption.
                       DESC

  s.homepage         = 'https://github.com/tripleCC/Laboratory/tree/master/HookLoadMethods'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'tripleCC' => 'triplec.linux@gmail.com' }
  s.source           = { :git => 'https://github.com/tripleCC/Laboratory.git', :tag => s.version}
  s.ios.deployment_target = '8.0'
  
  s.vendored_frameworks = "HookLoadMethods/#{s.name}.framework"
end
