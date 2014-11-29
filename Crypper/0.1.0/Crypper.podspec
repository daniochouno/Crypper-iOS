#
# Be sure to run `pod lib lint Crypper.podspec' to ensure this is a
# valid spec and remove all comments before submitting the spec.
#
# Any lines starting with a # are optional, but encouraged
#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = "Crypper"
  s.version          = "0.1.0"
  s.summary          = "A crypto wrapper for iOS projects."
  s.homepage         = "https://github.com/daniochouno/Crypper-iOS"
  s.license          = 'MIT'
  s.author           = { "Daniel Martínez" => "dmartinez@danielmartinez.info" }
  s.source           = { :git => "https://github.com/daniochouno/Crypper-iOS.git", :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/dmartinezinfo'

  s.platform     = :ios, '7.0'
  s.requires_arc = true

  s.source_files = 'Pod/Classes/**/*.{h,m}'
  s.resource_bundles = {
    'Crypper' => ['Pod/Assets/*.png']
  }

end
