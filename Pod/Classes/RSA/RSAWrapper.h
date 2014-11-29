//
//  RSAWrapper.h
//  Crypper
//
//  Created by Daniel Martínez Muñoz on 29/11/14.
//  Copyright (c) 2014 @dmartinezinfo. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "Utils.h"

@interface RSAWrapper : NSObject

+ (id)sharedInstance;

// Key Pair Generator:
- (NSArray *)generate:(size_t)keySizeInBitsLength;

// Encrypt a message:
- (NSString *)encrypt:(NSString *)message withPublicKeyAsBase64:(NSString *)key;

// Decrypt a message:
- (NSString *)decrypt:(NSString *)message withPrivateKeyAsBase64:(NSString *)key;

@end
