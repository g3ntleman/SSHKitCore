//
//  SSHKitSFTPDirectory.h
//  SSHKitCore
//
//  Created by vicalloy on 8/28/15.
//
//

#import <Foundation/Foundation.h>
#import "SSHKitCoreCommon.h"

@class SSHKitSFTP;

@interface SSHKitSFTPFile : NSObject

/**
 Property that stores the name of the underlaying file.
 Note that the file may also be a directory.
 */
@property (nonatomic, readonly) NSString *filename;

@property (nonatomic, readonly) NSString *fullFilename;

/** Property that declares whether the file is a directory or a regular file */
@property (nonatomic, readonly) BOOL isDirectory;

/** Returns the last modification date of the file */
@property (nonatomic, readonly) NSDate *modificationDate;

/** Returns the date of the last access to the file */
@property (nonatomic, readonly) NSDate *lastAccess;

/** Property that returns the file size in bytes */
@property (nonatomic, readonly) NSNumber *fileSize;

/** Returns the numeric identifier of the user that is the owner of the file */
@property (nonatomic, readonly) unsigned long ownerUserID;

/** Returns the numeric identifier of the group that is the owner of the file */
@property (nonatomic, readonly) unsigned long ownerGroupID;

/** Returns the file permissions in symbolic notation. E.g. drwxr-xr-x */
@property (nonatomic, readonly) NSString *permissions;

@property (nonatomic, readonly) char fileTypeLetter;

/** Returns the user defined flags for the file */
@property (nonatomic, readonly) u_long flags;

@property (nonatomic, readonly) SSHKitSFTP *sftp;
@property (nonatomic, readonly) BOOL directoryEof;
- (instancetype)init:(SSHKitSFTP *)sftp path:(NSString *)path;
- (NSInteger)closeDirectory;
- (SSHKitSFTPFile *)readDirectory;
// TODO read

@end
