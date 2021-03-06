//
//  SSHKitShellChannel.h
//  SSHKitCore
//
//  Created by Yang Yubo on 2/2/16.
//
//
#import <SSHKitCore/SSHKitCoreCommon.h>
#import "SSHKitChannel.h"

@protocol SSHKitShellChannelDelegate;

@interface SSHKitShellChannel : SSHKitChannel

- (void)changePtySizeToColumns:(NSInteger)columns rows:(NSInteger)rows;

@property (readonly, copy) NSString         *terminalType;
@property (readonly, nonatomic) NSInteger   columns;
@property (readonly, nonatomic) NSInteger   rows;

@end

@protocol SSHKitShellChannelDelegate <SSHKitChannelDelegate>

@required
- (void)channel:(SSHKitShellChannel *)channel didChangePtySizeToColumns:(NSInteger)columns rows:(NSInteger)rows withError:(NSError *)error;

@end
