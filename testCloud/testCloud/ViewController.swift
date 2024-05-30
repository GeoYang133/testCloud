//
//  ViewController.swift
//  testCloud
//
//  Created by 김원태 on 5/24/24.
//

import UIKit

class ViewController: UIViewController {
override func viewDidAppear(_ animated: Bool) {
    super.viewDidAppear( animated );

        //############################################################## AppSealing Code-Part BEGIN: DO NOT MODIFY THIS LINE !!!
        #if true  //--------------------------------------- APPSEALING-GetDeviceID [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
        let _instAppSealing_auto_generated1: AppSealingInterface = AppSealingInterface();
        let _appSealingDeviceID_auto_generated = String.init( cString: _instAppSealing_auto_generated1._GetAppSealingDeviceID() );
        let _appsealing_msg1 = "\n\n* AppSealing Device ID : ";
        print( _appsealing_msg1 + _appSealingDeviceID_auto_generated + "\n\n" );
        #endif    //--------------------------------------- APPSEALING-GetDeviceID [END] : DO NOT REMOVE THIS COMMENT !!!

        #if true  //--------------------------------------- APPSEALING-SecurityThreadCheck [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
        let _instAppSealing_auto_generated2: AppSealingInterface = AppSealingInterface();
        let _appsealing_tamper_auto_generated: Int32 = _instAppSealing_auto_generated2._IsAbnormalEnvironmentDetected();
        if ( _appsealing_tamper_auto_generated > 0 )
        {
            var _appsealing_msg2 = "Abnormal Environment Detected !!";
            if ( _appsealing_tamper_auto_generated & DETECTED_JAILBROKEN ) > 0
                { _appsealing_msg2 += "\n - Jailbroken"; }
            if ( _appsealing_tamper_auto_generated & DETECTED_DRM_DECRYPTED ) > 0
                { _appsealing_msg2 += "\n - Executable is not encrypted"; }
            if ( _appsealing_tamper_auto_generated & DETECTED_DEBUG_ATTACHED ) > 0
                { _appsealing_msg2 += "\n - App is debugged"; }
            if ( _appsealing_tamper_auto_generated & ( DETECTED_HASH_INFO_CORRUPTED | DETECTED_HASH_MODIFIED )) > 0
                { _appsealing_msg2 += "\n - App integrity corrupted"; }
            if ( _appsealing_tamper_auto_generated & ( DETECTED_CODESIGN_CORRUPTED | DETECTED_EXECUTABLE_CORRUPTED )) > 0
                { _appsealing_msg2 += "\n - App executable has corrupted"; }
            if (( _appsealing_tamper_auto_generated & DETECTED_CERTIFICATE_CHANGED ) > 0 )
                { _appsealing_msg2 += "\n - App has re-signed"; }
            if (( _appsealing_tamper_auto_generated & DETECTED_BLACKLIST_CORRUPTED ) > 0 )
                { _appsealing_msg2 += "\n - Blacklist/Whitelist has corrupted or missing"; }
            if (( _appsealing_tamper_auto_generated & DETECTED_CHEAT_TOOL ) > 0 )
                { _appsealing_msg2 += "\n - Cheat tool has detected"; }
            let _alertController_auto_generated = UIAlertController(title: "AppSealing Security", message: _appsealing_msg2, preferredStyle: .alert );
            _alertController_auto_generated.addAction(UIAlertAction(title: "Confirm", style: .default,
                                    handler: { (action:UIAlertAction!) -> Void in
            #if !DEBUG   // Debug mode does not kill app even if security threat has found
                                                exit(0);
            #endif
                                                } ));
                    self.present( _alertController_auto_generated, animated: true, completion: nil );
        }
        #endif    //--------------------------------------- APPSEALING-SecurityThreadCheck [END] : DO NOT REMOVE THIS COMMENT !!!
        #if true  //--------------------------------------- APPSEALING-GetCredential [BEGIN] : DO NOT REMOVE THIS COMMENT !!!
        let _instAppSealing_auto_generated3: AppSealingInterface = AppSealingInterface();
        let _appSealingCredential_auto_generated = String.init( cString: _instAppSealing_auto_generated3._GetEncryptedCredential() );
        let _appsealing_msg3 = "\n\n* AppSealing Credential : ";
        print( _appsealing_msg3 + _appSealingCredential_auto_generated + "\n\n" );
        // use thie credential value in your authentication function
        #endif    //--------------------------------------- APPSEALING-GetCredential [END] : DO NOT REMOVE THIS COMMENT !!!
        //############################################################## AppSealing Code-Part END: DO NOT MODIFY THIS LINE !!!

}

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }


}


