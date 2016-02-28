//
//  SSHKitPrivateKey.m
//  SSHKitCore
//
//  Created by Yang Yubo on 12/24/14.
//
//
#import "SSHKitCore+Protected.h"
#import "SSHKitKeyPair.h"

@implementation SSHKitKeyPair

+ (instancetype)keyFromFilePath:(NSString *)path withPassphraseHandler:(SSHKitAskPassphrasePrivateKeyBlock)passphraseHandler error:(NSError **)errPtr
{
    return [self keyFromString:path isBase64:NO withPassphraseHandler:passphraseHandler error:errPtr];
}

+ (instancetype)keyFromBase64:(NSString *)base64 withPassphraseHandler:(SSHKitAskPassphrasePrivateKeyBlock)passphraseHandler error:(NSError **)errPtr
{
    return [self keyFromString:base64 isBase64:YES withPassphraseHandler:passphraseHandler error:errPtr];
}


+ (instancetype)keyFromString:(NSString *)keyString isBase64:(BOOL)isBase64 withPassphraseHandler:(SSHKitAskPassphrasePrivateKeyBlock)passphraseHandler error:(NSError **)errPtr
{
    if (!keyString.length) {
        if (errPtr) *errPtr = [NSError errorWithDomain:SSHKitCoreErrorDomain
                                                  code:SSHKitErrorIdentityParseFailure
                                              userInfo:@{ NSLocalizedDescriptionKey : @"Content of private key is empty" }];
        return nil;
    }
    
    int ret = 0;
    SSHKitKeyPair *key = [[SSHKitKeyPair alloc] init];
    
    // import private key
    if (isBase64) {
        ret = ssh_pki_import_privkey_base64(keyString.UTF8String, NULL, _askPassphrase, (__bridge void *)(passphraseHandler), &key->_privateKey);
    } else {
        ret = ssh_pki_import_privkey_file(keyString.UTF8String, NULL, _askPassphrase, (__bridge void *)(passphraseHandler), &key->_privateKey);
    }
    
    switch (ret) {
        case SSH_OK:
            // success, try extract publickey
            break;
            
        case SSH_EOF:
            if (errPtr) *errPtr = [NSError errorWithDomain:SSHKitCoreErrorDomain
                                                      code:SSHKitErrorIdentityParseFailure
                                                  userInfo:@{
                                                             NSLocalizedDescriptionKey : @"Private key file doesn't exist or permission denied",
                                                             NSLocalizedRecoverySuggestionErrorKey : @"Please try again or import another private key."
                                                             }];
            return nil;
            
        default:
            if (errPtr) *errPtr = [NSError errorWithDomain:SSHKitCoreErrorDomain
                                                      code:SSHKitErrorIdentityParseFailure
                                                  userInfo:@{
                                                             NSLocalizedDescriptionKey : @"Could not parse private key",
                                                             NSLocalizedRecoverySuggestionErrorKey : @"Please try again or import another private key."
                                                             }];
            return nil;
    }
    
    // extract public key from private key
    ret = ssh_pki_export_privkey_to_pubkey(key->_privateKey, &key->_publicKey);
    
    
    switch (ret) {
        case SSH_OK:
            // success
            break;
            
        default:
            if (errPtr) *errPtr = [NSError errorWithDomain:SSHKitCoreErrorDomain
                                                      code:SSHKitErrorIdentityParseFailure
                                                  userInfo:@{ NSLocalizedDescriptionKey : @"Could not extract public key from private key" }];
            return nil;;
    }
    
    return key;
}

- (instancetype) initAsNewKeyPairOfType: (enum ssh_keytypes_e) type bitLength: (int) bitLength {
    
    int ret = ssh_pki_generate(type, bitLength, &_privateKey);
    if (ret == SSH_OK) {
        ret = ssh_pki_export_privkey_to_pubkey(_privateKey, &(_publicKey)); // expect this to work
        if (ret == SSH_OK) {
            return self;
        }
    }
    return nil;
}

- (void)dealloc
{
    if (_publicKey) {
        ssh_key_free(_publicKey);
    }
    if (_privateKey) {
        ssh_key_free(_privateKey);
    }
}

static int _askPassphrase(const char *prompt, char *buf, size_t len, int echo, int verify, void *userdata)
{
    if (!userdata) {
        return SSH_ERROR;
    }
    
    SSHKitAskPassphrasePrivateKeyBlock handler = (__bridge SSHKitAskPassphrasePrivateKeyBlock)userdata;
    
    if (!handler) {
        return SSH_ERROR;
    }
    
    NSString *password = handler();
    NSUInteger length = [password lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
    
    if (length && length<len) {
        strcpy(buf, password.UTF8String);
        return SSH_OK;
    }
    
    return SSH_ERROR;
}

@end
