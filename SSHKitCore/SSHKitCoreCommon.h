//
//  Common.h
//  SSHKitCore
//
//  Created by Yang Yubo on 11/14/14.
//
//
#import <Foundation/Foundation.h>

/**
 * Seeing a return statements within an inner block
 * can sometimes be mistaken for a return point of the enclosing method.
 * This makes inline blocks a bit easier to read.
 **/
#ifndef return_from_block
#define return_from_block  return
#endif

#define SSHKitLibsshErrorDomain @"SSHKit.libssh"
#define SSHKitCoreErrorDomain   @"SSHKit.Core"

typedef NS_ENUM(NSInteger, SSHKitErrorCode) {
    // error code from libssh
    SSHKitErrorNoError        = 0,
    SSHKitErrorRequestDenied,
    SSHKitErrorFatal,
    SSHKitErrorEINTR,
    
    // our error code
    SSHKitErrorTimeout       = 1005,
    SSHKitErrorHostKeyMismatch,
    SSHKitErrorAuthFailure,
    SSHKitErrorIdentityParseFailure,
    SSHKitErrorStop,
    SSHKitErrorConnectFailure,
    SSHKitErrorChannelFailure,
};

typedef NS_ENUM(NSInteger, SSHKitProxyType) {
    SSHKitProxyTypeDirect = -1,
    SSHKitProxyTypeSOCKS5 = 0,
    SSHKitProxyTypeSOCKS4,
    SSHKitProxyTypeHTTP,
    SSHKitProxyTypeSOCKS4A,
    SSHKitProxyTypeHTTPS, // just alias of SSHKitProxyTypeHTTP
};

typedef NS_ENUM(NSInteger, SSHKitChannelStage) {
    SSHKitChannelStageInitial = 0,  // channel has not been initiated correctly
    SSHKitChannelStageOpening,      // channel is opening
    SSHKitChannelStageReady,        // channel has been opened, we can read / write from the channel
    SSHKitChannelStageClosed,       // channel has been closed
};

/* All implementations MUST be able to process packets with an
 * uncompressed payload length of 32768 bytes or less and a total packet
 * size of 35000 bytes or less (including 'packet_length',
 *                              'padding_length', 'payload', 'random padding', and 'mac').
 */
#define SSHKIT_CORE_SSH_MAX_PAYLOAD 16384 // 16K should appropriate for both channel and sftp

typedef NSString *(^ SSHKitAskPassphrasePrivateKeyBlock)();

typedef void (^ SSHKitRequestRemoteForwardCompletionBlock)(BOOL success, uint16_t boundPort, NSError *error);

void SSHKitCoreInitiate();
void SSHKitCoreFinalize();
