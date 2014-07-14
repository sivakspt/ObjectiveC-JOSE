//
//  JsonWebToken.h
//  Primus
//
//  Created by Andy on 14/7/14.
//  Copyright (c) 2014 WowWee. All rights reserved.
//

#import <Foundation/Foundation.h>

@class JsonWebTokenBody;
@class JsonWebTokenHeader;

@interface JsonWebToken : NSObject

@property (nonatomic, strong) JsonWebTokenBody *body;
@property (nonatomic, strong) JsonWebTokenHeader *header;

@property (nonatomic, strong) NSString *sharedSecret;

+ (JsonWebToken *) jwtWithDict:(NSDictionary *)dict sharedSecret:(NSString *)sharedSecret;

- (JsonWebToken *) initSignedJWTWithSharedSecret:(NSString *)sharedSecret;

- (NSString *) jwtAsString;

@end

@interface JsonWebTokenBody : NSObject

// JWT Body Public Fields
@property (nonatomic, strong) NSString *issuer; // iss - optional
@property (nonatomic, strong) NSString *subject; // sub - optional
@property (nonatomic, strong) NSString *audience; // aud - optional
@property (nonatomic, strong) NSDate *expirationTime; // exp - optional
@property (nonatomic, strong) NSDate *notBefore; // nbf - optional
@property (nonatomic, strong) NSDate *issuedAt; // iat - optional
@property (nonatomic, strong) NSString *jwtIdentifier; // jti - optional

@property (nonatomic, strong) NSDictionary *privateClaims;

- (NSString *) encryptedString;

@end

@interface JsonWebTokenHeader : NSObject

@property (nonatomic, strong) NSString *type; // typ - optional
@property (nonatomic, strong) NSString *contentType; // cty - optional
@property (nonatomic, strong) NSString *CEKEncryption; // alg - Content Encryption Key (CEK) Algorithm
@property (nonatomic, strong) NSString *claimsEncryption; // enc - Claims Encryption

//@property (nonatomic, strong) NSString *compressionAlgorithm; // zip - Compression Algorithm
//4.1.5.  "jwk" (JSON Web Key) Header Parameter
//4.1.6.  "kid" (Key ID) Header Parameter
//4.1.7.  "x5u" (X.509 URL) Header Parameter
//4.1.8.  "x5c" (X.509 Certificate Chain) Header Parameter
//4.1.9.  "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
//4.1.10.  "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header Parameter
//4.1.11.  "typ" (Type) Header Parameter
//4.1.12.  "cty" (Content Type) Header Parameter
//4.1.13.  "crit" (Critical) Header Parameter

@property (nonatomic, strong) NSDictionary *extraFields;

// Unencrypted header fields
//@property (nonatomic, strong) NSString *issuer; // iss - optional
//@property (nonatomic, strong) NSString *subject; // sub - optional
//@property (nonatomic, strong) NSString *audience; // aud - optional

- (NSString *) encodedString;

@end


