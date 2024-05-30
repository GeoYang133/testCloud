#include "AppSealingiOS.h"

/////////////////////////////////////////////////////////////////////////////// LEA AREA BEGIN : DO NOT DELETE THIS LINE !!!!
bool __se_use_lea;
unsigned char __se_iv[16], __se_key[16], __se_key_table[248620];
/////////////////////////////////////////////////////////////////////////////// LEA AREA END : DO NOT DELETE THIS LINE !!!!

void iOS()
{
    Appsealing();
}

#if REACT_NATIVE_0_71
@implementation AppSealingInterfaceBridge
RCT_EXPORT_MODULE()

// Check the device for flash capabilities and return callback of success // or fail
RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(IsAbnormalEnvironmentDetectedRN)
{
    return [NSString stringWithFormat:@"%d", ObjC_IsAbnormalEnvironmentDetected()];
}
RCT_EXPORT_METHOD(ExitApp)
{
    exit( 0 );
}
@end
#endif


@interface AppSealingInterface()
@end

@implementation AppSealingInterface
- (instancetype)init
{
    return self;
}

-(int)_IsAbnormalEnvironmentDetected
{
    return ObjC_IsAbnormalEnvironmentDetected() ;
}

char appSealingDeviceID[64];
-(const char*)_GetAppSealingDeviceID
{
    if( ObjC_GetAppSealingDeviceID( appSealingDeviceID ) == 0 )
    {
        return appSealingDeviceID;
    }
    return "";
}

char appSealingCredential[290];
-(const char*)_GetEncryptedCredential
{
    if( ObjC_GetEncryptedCredential( appSealingCredential ) == 0 )
    {
        return appSealingCredential;
    }
    return "";
}

+( NSString* )_DSS: ( NSString* )string  // Decrypt String  (for Objective-C / Swift)
{
    char* ret = ObjC_DecryptString(( char* )[string UTF8String] );
    return [NSString stringWithUTF8String:ret];
}
+( NSString* )_DSC: ( char* )string  // Decrypt String (for C++)
{
    char* ret = ObjC_DecryptString( string );
    return [NSString stringWithUTF8String:ret];
}
@end
