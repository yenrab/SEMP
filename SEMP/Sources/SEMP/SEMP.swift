//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
//  Created by Barney, Lee on 1/2/25.
//

import Foundation
import SwErl
import Logging

public enum SEMPError: Error {
    case missingSecureEnclave
    case noSuchDirectory
    case emptyID
    case emptyPublicKeyPath
    case emptyPrivateKeyPath
    case missingPublicKeyFile
    case missingPrivateKeyFile
}

enum SEMP:GenServerBehavior {
    
    /// Starts a `SEMP` process and ensures necessary prerequisites are met.
    /// - Parameters:
    ///   - appID: A `String` representing the application ID. Must not be empty.
    ///   - encryptionKeysDir: A `String` representing the directory path where encryption keys are stored. The directory must exist.
    ///   - logger: An optional `Logger` instance for logging purposes.
    /// - Throws: This function can throw the following errors:
    ///   - `SEMPError.missingSecureEnclave`: If the Secure Enclave is not available on the device.
    ///   - `SEMPError.emptyID`: If the provided `appID` is empty.
    ///   - `SEMPError.noSuchDirectory`: If the specified `encryptionKeysDir` does not exist.
    ///   - Any errors propagated from the `GenServer.startLink` call.
    /// - Discussion:
    ///   This function verifies the availability of the Secure Enclave, ensures that the `appID` and `encryptionKeysDir` meet the required conditions, and starts a `SEMP` process.
    ///   The process is uniquely named "SEMP" as there will be only one instance per device.
    /// - Complexity: O(1) for checks and process startup.
    /// - Author: Lee Barney
    /// - Version: 0.2
    static func startLink(appID: String, encryptionKeysDir: String, Logger logger: Logger?) throws{
        if !isSecureEnclaveAvailable(){
            throw SEMPError.missingSecureEnclave
        }
        if appID.isEmpty{
            throw SEMPError.emptyID
        }
        if !FileManager.default.fileExists(atPath: encryptionKeysDir) {
            throw SEMPError.noSuchDirectory
        }
        try GenServer.startLink("SEMP", SEMP.self, (appID,encryptionKeysDir,logger))//there will only be one SEMP per device so it is safe hardcode the name here.
    }
    
    /// Starts a `SEMP` process and ensures the necessary encryption keys and directories are available.
    /// - Parameters:
    ///   - encryptionKeysDir: A `String` representing the directory path where encryption keys are stored. The directory must exist.
    ///   - publicKeyFilePath: A `String` representing the file path to the public key. The file must exist and the path must not be empty.
    ///   - privateKeyFilePath: A `String` representing the file path to the private key. The file must exist and the path must not be empty.
    ///   - logger: An optional `Logger` instance for logging purposes.
    /// - Throws: This function can throw the following errors:
    ///   - `SEMPError.emptyPublicKeyPath`: If the `publicKeyFilePath` is empty.
    ///   - `SEMPError.missingPublicKeyFile`: If the public key file does not exist at the specified path.
    ///   - `SEMPError.emptyPrivateKeyPath`: If the `privateKeyFilePath` is empty.
    ///   - `SEMPError.missingPrivateKeyFile`: If the private key file does not exist at the specified path.
    ///   - `SEMPError.noSuchDirectory`: If the specified `encryptionKeysDir` does not exist.
    ///   - Any errors propagated from the `GenServer.startLink` call.
    /// - Discussion:
    ///   This function verifies that the public and private key file paths and the encryption keys directory meet the required conditions before starting a `SEMP` process.
    ///   The process is uniquely named "SEMP" as there will be only one instance per device.
    /// - Complexity: O(1) for checks and process startup.
    /// - Author: Lee Barney
    /// - Version: 0.2
    static func startLink(encryptionKeysDir: String, publicKeyFilePath:String, privateKeyFilePath:String, Logger logger: Logger?) throws{
        
        if publicKeyFilePath.isEmpty{
            throw SEMPError.emptyPublicKeyPath
        }
        if !FileManager.default.fileExists(atPath: publicKeyFilePath) {
            throw SEMPError.missingPublicKeyFile
        }
        if privateKeyFilePath.isEmpty{
            throw SEMPError.emptyPrivateKeyPath
        }
        if !FileManager.default.fileExists(atPath: privateKeyFilePath) {
            throw SEMPError.missingPrivateKeyFile
        }
        // Optionally validate the directory exists
        if !FileManager.default.fileExists(atPath: encryptionKeysDir) {
            throw SEMPError.noSuchDirectory
        }
        try GenServer.startLink("SEMP", SEMP.self, (publicKeyFilePath,privateKeyFilePath,encryptionKeysDir,logger))//there will only be one SEMP per device so it is safe hardcode the name here.
    }

    /// Validates the function's incomming data to produce intial state for the SEMP GenServer.
    /// - Parameters:
    ///   - data: An optional `Any` representing the input data. Expected to be one of the following:
    ///     - A32-tuple: `(String, String, Logger?)`, representing an app ID, a public keys directory, and an optional logger.
    ///     - A 4-tuple: `(String, String, String, Logger?)`, representing a public key path, a private key path, a public keys directory, and an optional logger.
    /// - Returns: The validated initial GenServer state data if it matches one of the expected formats, otherwise `nil`.
    /// - Discussion:
    ///   This function validates and processes the input data. If the input is a 3-tuple, it logs validation for an enclave system.
    ///   If the input is a 4-tuple, it logs validation for a non-enclave system. For invalid formats or `nil` data, an error message is logged, and `nil` is returned as the initial state data for the SEMP GenServer.
    /// - Complexity: O(1) for validation and logging.
    /// - Author: Lee Barney
    /// - Version: 0.2
    static func initializeData(_ data: Any?) -> Any? {
        // Ensure `data` is not nil
        guard let validData = data else {
            print("Error: Data cannot be nil.")
            return nil
        }
        
        // Handle if `data` is a 2-tuple with an app ID, directory path, and optional Logger
        if let tuple = validData as? (String, String, Logger?) {
            let (appID, publicKeysDir, logger) = tuple
            
            logger?.log(level: .info, "validated enclave system with: App ID - \(appID), Public Keys Directory - \(publicKeysDir)")
            
            //:TODO Generate public and private keys in enclave
            return tuple
        }
        
        // Handle if `data` is a 3-tuple with key paths, directory path, and optional Logger
        else if let tuple = validData as? (String, String, String, Logger?) {
            let (publicKeyPath, privateKeyPath, publicKeysDir, logger) = tuple
            
            logger?.log(level: .info, "validated non-enclave stystem with: Public Key Path - \(publicKeyPath), Private Key Path - \(privateKeyPath), Public Keys Directory - \(publicKeysDir)")
            ///TODO: load pub and priv keys. make them, the encryption public keys dir, and the logger be the returned tuple.
            return tuple
        }
        
        // If data doesn't match any expected type
        print("Error: Invalid data format. Expected (AppID, PublicKeysDir,Logger?) or (PublicKeyPath, PrivateKeyPath, PublicKeysDir,Logger).")
        return nil
    }
    
    static func terminateCleanup(reason: String, data: Any?) {
        print("hello world")
    }
    
    static func handleCast(request: Any, data: Any?) -> Any? {
        return nil
    }
    
    static func handleCall(request: Any, data: Any) -> (Any, Any) {
        return(2,4)
    }
    
    
}
