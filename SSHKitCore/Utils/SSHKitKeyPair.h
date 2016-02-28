//
//  SSHKitPrivateKey.h
//  SSHKitCore
//
//  Created by Yang Yubo on 12/24/14.
//
//

#import <Foundation/Foundation.h>
#import "SSHKitCore.h"
#import <libssh/libssh.h>

@interface SSHKitKeyPair : NSObject

- (instancetype) initAsNewKeyPairOfType: (enum ssh_keytypes_e) type bitLength: (int) bitLength;

+ (instancetype)keyFromFilePath:(NSString *)path withPassphraseHandler:(SSHKitAskPassphrasePrivateKeyBlock)passphraseHandler error:(NSError **)errPtr;

+ (instancetype)keyFromBase64:(NSString *)base64 withPassphraseHandler:(SSHKitAskPassphrasePrivateKeyBlock)passphraseHandler error:(NSError **)errPtr;

@end
