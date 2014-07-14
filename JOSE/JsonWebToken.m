//
//  JsonWebToken.m
//
//  Implements JSON Web Tokens - http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
//
//  Created by Andy on 14/7/14.
//  Copyright (c) 2014 WowWee. All rights reserved.
//

#import "JsonWebToken.h"
#import <CommonCrypto/CommonHMAC.h>

@implementation JsonWebToken

- (JsonWebToken *) initSignedJWTWithSharedSecret:(NSString *)sharedSecret {
    if (self = [self init]) {
        self.sharedSecret = sharedSecret;
        self.header.CEKEncryption = @"HS256";
    }
    
    return self;
}

- (JsonWebToken *) init {
    if (self = [super init]) {
        self.body = [[JsonWebTokenBody alloc] init];
        self.header = [[JsonWebTokenHeader alloc] init];
    }
    return self;
}

+ (JsonWebToken *) jwtWithDict:(NSDictionary *)dict sharedSecret:(NSString *)sharedSecret {
    JsonWebToken *jsonWebToken = [[JsonWebToken alloc] initSignedJWTWithSharedSecret:sharedSecret];
    jsonWebToken.body.privateClaims = dict;
    
    return jsonWebToken;
}

- (void) setBody:(JsonWebTokenBody *)body {
    NSAssert(body, @"Body cannot be nil");
    _body = body;
}

- (void) setHeader:(JsonWebTokenHeader *)header {
    NSAssert(header, @"Header cannot be nil");
    _header = header;
}

- (NSString *) jwtAsString {
    return [NSString stringWithFormat:@"%@.%@.%@", [self.header encodedString], [self.body encryptedString], [self computeSignature]];
}

- (NSString *) computeSignature {
    if ([self.header.CEKEncryption isEqualToString:@"none"]) {
        return nil;
    }
    
    NSString *stringToHash = [NSString stringWithFormat:@"%@.%@", [self.header encodedString], [self.body encryptedString]];
        
    if ([self.header.CEKEncryption isEqualToString:@"HS256"]) {
        return [self computeHmac256WithString:stringToHash];
    }
    
    // No match for any algorithems
    return nil;
}

#pragma mark - Signature Algorithems
- (NSString *) computeHmac256WithString:(NSString *)stringToHash {
    NSData *secretData = [self.sharedSecret dataUsingEncoding:NSUTF8StringEncoding];
    NSData *paramData = [stringToHash dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* hash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH ];
    CCHmac(kCCHmacAlgSHA256, secretData.bytes, secretData.length, paramData.bytes, paramData.length, hash.mutableBytes);
    return [hash base64EncodedStringWithOptions:0];
}

@end

#pragma mark - JsonWebTokenBody

@interface JsonWebTokenBody()
@property (nonatomic, strong) NSDictionary *reservedFields;
@end

@implementation JsonWebTokenBody

- (JsonWebTokenBody *) init {
    if (self = [super init]) {
        self.reservedFields = @{@"iss": @"issuer",
                                @"sub": @"subject",
                                @"aud": @"audience",
                                @"exp": @"expirationTime",
                                @"nbf": @"notBefore",
                                @"iat": @"issuedAt",
                                @"jti": @"jwtIdentifier"};
    }
    
    return nil;
}

- (NSString *) encodedString {
    NSMutableDictionary *dict = [NSMutableDictionary new];
    
    for (NSString *key in self.privateClaims) {
        // If the private fields over-ride any of our reserved fields, then set the reserved fields to match
        if ([self.reservedFields objectForKey:key]) {
            [self setValue:self.privateClaims[key] forKey:self.reservedFields[key]];
        } else {
            [dict setObject:self.privateClaims[key] forKey:key];
        }
    }
    
    if (self.issuer) {
        [dict setObject:self.issuer forKey:@"iss"];
    }
    
    if (self.subject) {
        [dict setObject:self.subject forKey:@"sub"];
    }
    
    if (self.audience) {
        [dict setObject:self.audience forKey:@"aud"];
    }
    
    if (self.expirationTime) {
        [dict setObject:self.expirationTime forKey:@"exp"];
    }
    
    if (self.notBefore) {
        [dict setObject:self.notBefore forKey:@"nbf"];
    }
    
    if (self.issuedAt) {
        [dict setObject:self.issuedAt forKey:@"iat"];
    }
    
    if (self.jwtIdentifier) {
        [dict setObject:self.jwtIdentifier forKey:@"jti"];
    }
    
    NSError *error;
    NSData *encodedData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&error];
    
    if (error) {
        NSLog(@"ERROR ENCODING BODY DATA: %@", error);
        return nil;
    }
    
    return [encodedData base64EncodedStringWithOptions:0];
}

- (NSString *) encryptedString {
    NSString *encoded = [self encodedString];
    
    return encoded;
}
    
@end

#pragma mark - JsonWebTokenHeader

@interface JsonWebTokenHeader()
@property (nonatomic, strong) NSDictionary *reservedFields;
@end

@implementation JsonWebTokenHeader

- (JsonWebTokenHeader *) init {
    if (self = [super init]) {
        self.reservedFields = @{@"typ": @"type",
                                @"cty": @"contentType",
                                @"alg": @"CEKEncryption",
                                @"enc": @"claimsEncryption"};
        
        // Mandatory fields (with sane defaults)
        self.type = @"JWT";
        self.CEKEncryption = @"none";
    }
    
    return self;
}

- (void) setCEKEncryption:(NSString *)CEKEncryption {
    bool valid = NO;
    
    if ([CEKEncryption isEqualToString:@"HMS256"]) {
        valid = YES;
    } else if ([CEKEncryption isEqualToString:@"none"]) {
        valid = YES;
    } else {
        valid = NO;
    }
    
    NSAssert(valid, @"Must provide a supported CEKEncryption type");
    
    _CEKEncryption = CEKEncryption;
}

- (void) setClaimsEncryption:(NSString *)claimsEncryption {
    bool valid = NO;
    
    if ([claimsEncryption isEqualToString:@"RSA1_5"]) {
        valid = YES;
    } else if ([claimsEncryption isEqualToString:@"A128KW"]) {
        valid = YES;
    } else if ([claimsEncryption isEqualToString:@"A256KW"]) {
        valid = YES;
    } else if ([claimsEncryption isEqualToString:@"A128CBC-HS256"]) {
        valid = YES;
    } else if ([claimsEncryption isEqualToString:@"A256CBC-HS512"]) {
        valid = YES;
    } else {
        valid = NO;
    }
    
    NSAssert(valid, @"Must provide a supported Claims Encryption type");
    
    _claimsEncryption = claimsEncryption;
}


- (NSString *) encodedString {
    NSMutableDictionary *dict = [NSMutableDictionary new];
    
    for (NSString *key in self.extraFields) {
        // If the private fields over-ride any of our reserved fields, then set the reserved fields to match
        if ([self.reservedFields objectForKey:key]) {
            [self setValue:self.extraFields[key] forKey:self.reservedFields[key]];
        } else {
            [dict setObject:self.extraFields[key] forKey:key];
        }
    }
    
    if (self.type) {
        [dict setObject:self.type forKey:@"typ"];
    }
    
    if (self.contentType) {
        [dict setObject:self.contentType forKey:@"cty"];
    }
    
    if (self.CEKEncryption) {
        [dict setObject:self.CEKEncryption forKey:@"alg"];
    }
    
    if (self.claimsEncryption) {
        [dict setObject:self.claimsEncryption forKey:@"enc"];
    }
    
    NSError *error;
    NSData *encodedData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:&error];
    
    if (error) {
        NSLog(@"ERROR ENCODING HEADER DATA: %@", error);
        return nil;
    }
    
    return [encodedData base64EncodedStringWithOptions:0];
}

@end