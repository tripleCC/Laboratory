#
# Be sure to run `pod lib lint OCHooking.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'A4LoadMeasure'
  s.version          = '0.1.1'

  s.summary          = 'Measure load method execution time.'

  s.description      = <<-DESC
A tool used to measure load method execution time.
                       DESC

  s.homepage         = 'https://github.com/tripleCC/Laboratory/tree/master/HookLoadMethods'
  s.license          = { :type => 'MIT', :text => <<-DOC
    Copyright (c) 2019 tripleCC <triplec.linux@gmail.com>
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
                                                    DOC
 }
  s.author           = { 'tripleCC' => 'triplec.linux@gmail.com' }
  s.source           = { :http => "https://github.com/tripleCC/Laboratory/releases/download/#{s.version}/#{s.name}.zip"}
  s.ios.deployment_target = "8.0"
  # s.osx.deployment_target = "10.11"
  # s.tvos.deployment_target = "9.0"
  # s.watchos.deployment_target = "2.0"
  
  s.vendored_frameworks = "#{s.name}.framework"
end
