//
//  SSHKitSFTP.m
//  SSHKitCore
//
//  Created by vicalloy on 8/26/15.
//
//

#import "SSHKitCore+Protected.h"
#import "SSHKitChannel.h"

@interface SSHKitSFTPChannel()
@end

@implementation SSHKitSFTPChannel

+ (void)freeSFTPAttributes:(sshkit_sftp_attributes)attributes {
    sftp_attributes_free(attributes);
}

- (void)channel:(SSHKitChannel *)channel didReadStdoutData:(NSData *)data {
    if (self.stage != SSHKitChannelStageReadWrite) {
        return;
    }
    for (SSHKitSFTPFile *file in _remoteFiles) {
        [file channel:self didReadStdoutData:data];
    }
}

- (void)_doProcess_del {
    [super _doProcess];
    if (self.stage != SSHKitChannelStageReadWrite) {
        return;
    }
    for (SSHKitSFTPFile *file in _remoteFiles) {
        [file _doProcess];
    }
}

- (SSHKitSFTPFile *)openDirectory:(NSString *)path {
    SSHKitSFTPFile* directory = [[SSHKitSFTPFile alloc]init:self path:path isDirectory:YES];
    // TODO handle error
    [directory open];
    return directory;
}

- (SSHKitSFTPFile *)openFile:(NSString *)path {
    SSHKitSFTPFile* file = [[SSHKitSFTPFile alloc]init:self path:path isDirectory:NO];
    // TODO handle error
    [file open];
    return file;
}

- (NSMutableArray *)remoteFiles {
    if (_remoteFiles == nil) {
        _remoteFiles = [@[]mutableCopy];
    }
    return _remoteFiles;
}

@end