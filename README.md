# Crypper

[![CI Status](http://img.shields.io/travis/Daniel Martínez/Crypper.svg?style=flat)](https://travis-ci.org/Daniel Martínez/Crypper)
[![Version](https://img.shields.io/cocoapods/v/Crypper.svg?style=flat)](http://cocoadocs.org/docsets/Crypper)
[![License](https://img.shields.io/cocoapods/l/Crypper.svg?style=flat)](http://cocoadocs.org/docsets/Crypper)
[![Platform](https://img.shields.io/cocoapods/p/Crypper.svg?style=flat)](http://cocoadocs.org/docsets/Crypper)

## Usage

First, you can generate a RSA key pair using:

// Generate an array with Public and Private keys of 2048 bits.
NSArray *keys = [[RSAWrapper sharedInstance] generate:2048];  

Now you can encypt a message:

NSString *encrypted = [[RSAWrapper sharedInstance] encrypt:@"HelloCrypper" withPublicKeyAsBase64:[keys objectAtIndex:0]];

and decrypt:

NSString *message = [[RSAWrapper sharedInstance] decrypt:encrypted withPrivateKeyAsBase64:[keys objectAtIndex:1]];

## Installation

Crypper is available through [CocoaPods](http://cocoapods.org). To install
it, simply add the following line to your Podfile:

pod "Crypper"

## Author

Daniel Martínez, dmartinez@danielmartinez.info

## License

Crypper is available under the MIT license. See the LICENSE file for more info.
