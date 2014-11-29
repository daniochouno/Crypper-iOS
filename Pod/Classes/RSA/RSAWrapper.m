//
//  RSAWrapper.m
//  Crypper
//
//  Created by Daniel Martínez Muñoz on 29/11/14.
//  Copyright (c) 2014 @dmartinezinfo. All rights reserved.
//

#import "RSAWrapper.h"

NSString *const kTAG_PUBLIC_KEY = @"crypper.key.public";
NSString *const kTAG_PRIVATE_KEY = @"crypper.key.private";

@interface RSAWrapper() {
@private
    NSOperationQueue *queue;
}

@end

@implementation RSAWrapper

- (id)init {
    if (self = [super init]) {
        queue = [[NSOperationQueue alloc] init];
    }
    return self;
}

+ (id)sharedInstance {
    static RSAWrapper *_RSAWrapper = nil;
    static dispatch_once_t onceToken;
    dispatch_once (&onceToken, ^{
        _RSAWrapper = [[self alloc] init];
    });
    return _RSAWrapper;
}

- (NSArray *)generate:(size_t)keySizeInBitsLength {
    
    // Tags for Public and Private Keys:
    NSData *_publicTag = [kTAG_PUBLIC_KEY dataUsingEncoding:NSUTF8StringEncoding];
    NSData *_privateTag = [kTAG_PRIVATE_KEY dataUsingEncoding:NSUTF8StringEncoding];
    
    // Delete current keys:
    [self deleteCurrentKeys];
    
    // Configuration for Private Key:
    NSMutableDictionary *privateKeyData = [NSMutableDictionary dictionary];
    [privateKeyData setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyData setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // Configuration for Public Key:
    NSMutableDictionary *publicKeyData = [NSMutableDictionary dictionary];
    [publicKeyData setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyData setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    // Main configuration:
    NSMutableDictionary *mainData = [NSMutableDictionary dictionary];
    [mainData setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [mainData setObject:[NSNumber numberWithUnsignedInteger:keySizeInBitsLength] forKey:(__bridge id)kSecAttrKeySizeInBits];
    [mainData setObject:privateKeyData forKey:(__bridge id)kSecPrivateKeyAttrs];
    [mainData setObject:publicKeyData forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // Execution:
    SecKeyRef publicKeyRef = NULL;
    SecKeyRef privateKeyRef = NULL;
    OSStatus sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)mainData, &publicKeyRef, &privateKeyRef);
    if (sanityCheck != noErr) {
        return nil;
    }
    
    // Store Keys in array:
    NSString *privateKey = [[self keyRefToData:kTAG_PRIVATE_KEY] base64EncodedStringWithOptions:0];
    NSString *publicKey = [self prepareToExportKey:[self keyRefToData:kTAG_PUBLIC_KEY]];
    
    // Remove all references to keys:
    publicKeyRef = NULL;
    privateKeyRef = NULL;
    [self deleteCurrentKeys];
    
    // Array:
    NSArray *keys = [NSArray arrayWithObjects:publicKey, privateKey, nil];
    
    privateKey = NULL;
    publicKey = NULL;
    
    return keys;
    
}

- (void)deleteCurrentKeys {
    
    OSStatus sanityCheck = noErr;
    
    // Configuration for Private Key:
    NSMutableDictionary *privateKeyData = [NSMutableDictionary dictionary];
    [privateKeyData setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKeyData setObject:kTAG_PRIVATE_KEY forKey:(__bridge id)kSecAttrApplicationTag];
    [privateKeyData setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Delete the private key:
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)privateKeyData);
    
    // Configuration for Public Key:
    NSMutableDictionary *publicKeyData = [NSMutableDictionary dictionary];
    [publicKeyData setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKeyData setObject:kTAG_PUBLIC_KEY forKey:(__bridge id)kSecAttrApplicationTag];
    [publicKeyData setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Delete the public key:
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)publicKeyData);
    
}

- (NSData *)keyRefToData:(NSString *)tag {
    
    NSData *_tag = [tag dataUsingEncoding:NSUTF8StringEncoding];
    
    // Configuration:
    NSMutableDictionary *data = [NSMutableDictionary dictionary];
    [data setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [data setObject:_tag forKey:(__bridge id)kSecAttrApplicationTag];
    [data setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [data setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnData];
    
    // Get the key bits:
    CFTypeRef _keyBits = NULL;
    OSStatus sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)data, (CFTypeRef *)&_keyBits);
    if (sanityCheck != noErr) {
        _keyBits = NULL;
    }
    
    return (__bridge NSData*)_keyBits;
    
}

- (NSString *)prepareToImportKey:(NSString *)keyAsBase64 {
    
    NSData *rawFormattedKey = [[NSData alloc] initWithBase64EncodedString:keyAsBase64 options:0];
    
    unsigned char * bytes = (unsigned char *)[rawFormattedKey bytes];
    size_t bytesLen = [rawFormattedKey length];
    
    size_t i = 0;
    if (bytes[i++] != 0x30)
        return FALSE;
    
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i] != 0x30)
        return FALSE;
    
    i += 15;
    
    if (i >= bytesLen - 2)
        return FALSE;
    
    if (bytes[i++] != 0x03)
        return FALSE;
    
    if (bytes[i] > 0x80)
        i += bytes[i] - 0x80 + 1;
    else
        i++;
    
    if (i >= bytesLen)
        return FALSE;
    
    if (bytes[i++] != 0x00)
        return FALSE;
    
    if (i >= bytesLen)
        return FALSE;
    
    NSData * extractedKey = [NSData dataWithBytes:&bytes[i] length:bytesLen - i];
    
    return [extractedKey base64EncodedStringWithOptions:0];
    
}

- (NSString *)prepareToExportKey:(NSData *)keyBits {
    
    static const unsigned char _encodedRSAEncryptionOID[15] = {
        
        /* Sequence of length 0xd made up of OID followed by NULL */
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        
    };
    
    unsigned char builder[15];
    NSMutableData * encKey = [[NSMutableData alloc] init];
    int bitstringEncLength;
    
    if ([keyBits length ] + 1 < 128) {
        bitstringEncLength = 1;
    } else {
        bitstringEncLength = (int)(([keyBits length ] + 1) / 256) + 2;
    }
    
    builder[0] = 0x30;
    
    size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
    [keyBits length];
    size_t j = encodeLength(&builder[1], i);
    [encKey appendBytes:builder length:j +1];
    
    [encKey appendBytes:_encodedRSAEncryptionOID length:sizeof(_encodedRSAEncryptionOID)];
    
    builder[0] = 0x03;
    j = encodeLength(&builder[1], [keyBits length] + 1);
    builder[j+1] = 0x00;
    [encKey appendBytes:builder length:j + 2];
    
    [encKey appendData:keyBits];
    
    return [encKey base64EncodedStringWithOptions:0];
    
}

size_t encodeLength(unsigned char * buf, size_t length) {
    
    // encode length in ASN.1 DER format
    if (length < 128) {
        buf[0] = length;
        return 1;
    }
    
    size_t i = (length / 256) + 1;
    buf[0] = i + 0x80;
    for (size_t j = 0 ; j < i; ++j) {
        buf[i - j] = length & 0xFF;
        length = length >> 8;
    }
    
    return i + 1;
}


/*
 *
 * Encryption.
 */

- (NSString *)encrypt:(NSString *)message withPublicKeyAsBase64:(NSString *)key {
    // Encryption with Public Key:
    return [self encrypt:message withKeyAsBase64:key tag:kTAG_PUBLIC_KEY];
}

- (NSString *)encrypt:(NSString *)message withKeyAsBase64:(NSString *)key tag:(NSString *)tag {
    
    // NSString to NSData:
    NSData *plainBytes = [message dataUsingEncoding:NSUTF8StringEncoding];
    
    // Import Key:
    NSString *_key = [self prepareToImportKey:key];
    
    if ((_key != nil) && ([_key length] > 0)) {
        
        // Delete current keys:
        [self deleteCurrentKeys];
        
        NSData *_dataKey = [[NSData alloc] initWithBase64EncodedString:_key options:0];
        
        NSData *_tag = [tag dataUsingEncoding:NSUTF8StringEncoding];
        
        // Key configuration:
        NSMutableDictionary *keyData = [NSMutableDictionary dictionary];
        [keyData setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [keyData setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [keyData setObject:_tag forKey:(__bridge id)kSecAttrApplicationTag];
        [keyData setObject:_dataKey forKey:(__bridge id)kSecValueData];
        [keyData setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
        
        CFTypeRef persistPeer = NULL;
        OSStatus sanityCheck = SecItemAdd((__bridge CFDictionaryRef)keyData, &persistPeer);
        if (sanityCheck != noErr) {
            return nil;
        }
        
        SecKeyRef keyRef = NULL;
        
        // Configuration:
        NSMutableDictionary *data = [NSMutableDictionary dictionary];
        [data setObject:(__bridge id)persistPeer forKey:(__bridge id)kSecValuePersistentRef];
        [data setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        // Get the persistent key reference.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)data, (CFTypeRef *)&keyRef);
        if (sanityCheck != noErr) {
            return nil;
        }
        
        // Delete data:
        [data removeAllObjects];
        [keyData removeAllObjects];
        CFRelease(persistPeer);
        
        if (keyRef != nil) {
            
            size_t cipherBufferSize = SecKeyGetBlockSize(keyRef);
            uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
            memset((void *)cipherBuffer, 0*0, cipherBufferSize);
            
            size_t blockSize = cipherBufferSize - 11;
            size_t blockCount = (size_t)ceil([plainBytes length] / (double)blockSize);
            NSMutableData *encryptedData = [NSMutableData dataWithCapacity:0];
            
            for (int i = 0; i < blockCount; i++) {
                
                int bufferSize = (int)MIN(blockSize,[plainBytes length] - i * blockSize);
                NSData *buffer = [plainBytes subdataWithRange:NSMakeRange(i * blockSize, bufferSize)];
                
                // Encrypt:
                OSStatus sanityCheck = SecKeyEncrypt (keyRef,
                                                      kSecPaddingNone,
                                                      (const uint8_t *)[buffer bytes],
                                                      [buffer length],
                                                      cipherBuffer,
                                                      &cipherBufferSize);
                if (sanityCheck != noErr) {
                    return nil;
                }
                
                NSData *encryptedBytes = [NSData dataWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
                [encryptedData appendData:encryptedBytes];
                
            }
            
            if (cipherBuffer) free(cipherBuffer);
            
            keyRef = NULL;
            
            // Delete current keys:
            [self deleteCurrentKeys];
            
            return [encryptedData base64EncodedStringWithOptions:0];
            
        } else {
            return nil;
        }
        
    } else {
        return nil;
    }
    
}


/*
 *
 * Decryption.
 */

- (NSString *)decrypt:(NSString *)message withPrivateKeyAsBase64:(NSString *)key {
    // Decryption with Private Key:
    return [self decrypt:message withKeyAsBase64:key tag:kTAG_PRIVATE_KEY];
}

- (NSString *)decrypt:(NSString *)message withKeyAsBase64:(NSString *)key tag:(NSString *)tag {
    
    NSData *wrappedSymmetricKey = [[NSData alloc] initWithBase64EncodedString:message options:0];
    
    NSData *_key = [Utils dataWithBase64EncodedString:key];
    if (_key == nil) {
        return nil;
    }
    
    // Delete current keys:
    [self deleteCurrentKeys];
    
    NSData *_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Configuration:
    NSMutableDictionary *data = [NSMutableDictionary dictionary];
    [data setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [data setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [data setObject:_tag forKey:(__bridge id)kSecAttrApplicationTag];
    [data setObject:_key forKey:(__bridge id)kSecValueData];
    [data setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)kSecAttrKeyClass];
    [data setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnPersistentRef];
    
    // Add Key:
    CFTypeRef persistKey = nil;
    OSStatus sanityCheck = SecItemAdd((__bridge CFDictionaryRef)data, &persistKey);
    if ((sanityCheck != noErr) && (sanityCheck != errSecDuplicateItem)) {
        return nil;
    }
    
    if (persistKey != nil) {
        CFRelease(persistKey);
    }
    
    // Set new configuration:
    [data removeObjectForKey:(__bridge id)kSecValueData];
    [data removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [data setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [data setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Get Key Ref:
    SecKeyRef keyRef = nil;
    sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)data, (CFTypeRef *)&keyRef);
    if (sanityCheck != noErr) {
        return nil;
    }
    
    if ((keyRef != nil) && (wrappedSymmetricKey != nil)) {
        
        size_t cipherBufferSize = SecKeyGetBlockSize(keyRef);
        size_t keyBufferSize = [wrappedSymmetricKey length];
        
        NSMutableData *bits = [NSMutableData dataWithLength:keyBufferSize];
        OSStatus sanityCheck = SecKeyDecrypt(keyRef,
                                             kSecPaddingNone,
                                             (const uint8_t *) [wrappedSymmetricKey bytes],
                                             cipherBufferSize,
                                             [bits mutableBytes],
                                             &keyBufferSize);
        
        if (sanityCheck != noErr) {
            return nil;
        }
        
        [bits setLength:keyBufferSize];
        
        unsigned char *buffer[keyBufferSize];
        [bits getBytes:buffer length:keyBufferSize];
        
        NSString *plainString = [[NSString alloc] initWithBytes:buffer length:keyBufferSize encoding:NSUTF8StringEncoding];
        
        // Delete current keys:
        [self deleteCurrentKeys];
        keyRef = nil;
        
        return plainString;
        
    } else {
        return nil;
    }
    
}

@end
