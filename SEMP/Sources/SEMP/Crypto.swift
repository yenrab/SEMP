//
//  Crypto.swift
//  SEMP

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
import Security

/// Checks whether the Secure Enclave is available on the device.
/// - Returns: A `Bool` indicating the availability of the Secure Enclave.
///   - `true`: The Secure Enclave is available.
///   - `false`: The Secure Enclave is not available or accessible.
/// - Discussion:
///   This function performs a query against the Secure Enclave to verify its presence. The query is executed with the `kSecAttrTokenIDSecureEnclave` attribute to ensure Secure Enclave-specific validation.
///   The function returns `true` if the status of the query is either `errSecItemNotFound` (no items found but Enclave is accessible) or `errSecSuccess` (item found).
/// - Complexity: O(1) for the query operation assuming indexed lookups.
/// - Author: Lee Barney
/// - Version: 0.2
func isSecureEnclaveAvailable() -> Bool {
    let query: [String: Any] = [
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecClass as String: kSecClassKey
    ]
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    print("Secure Enclave query status: \(status)")
    return status == errSecItemNotFound || status == errSecSuccess
}


/// Generates an asymmetric key pair in the Secure Enclave.
/// - Parameters:
///   - appTag: A `String` that acts as a unique identifier for the key pair. It is stored as the application tag for the private key.
/// - Returns: A tuple containing:
///   - `status`: A `String` indicating the result of the operation. Possible values are "ok" (success) or "error" (failure).
///   - `reason`: An optional `String` providing the reason for a failure, or `nil` if the operation was successful.
/// - Discussion:
///   This function leverages the Secure Enclave to generate an elliptic curve key pair with a size of 256 bits. The key is made persistent and tagged with the provided application tag.
///   If key generation fails, the function captures and returns a description of the error.
/// - Complexity:O((log n)^3)
/// - Author: Lee Barney
/// - Version: 0.2
func generateEnclaveKeyPair(appTag: String) -> (status: String, reason: String?) {
    let tag = appTag.data(using: .utf8)!
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave, // Ensure Secure Enclave usage
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true, // Make key persistent
            kSecAttrApplicationTag as String: tag
        ]
    ]
    
    var error: Unmanaged<CFError>?
    guard let _ = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let failureReason = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
        print("Key pair generation failed: \(failureReason)")
        return ("error", failureReason)
    }
    
    print("Key pair generated successfully.")
    return ("ok", nil)
}

/// Decrypts data using a private key stored in the Secure Enclave and an optional encryption algorithm.
/// - Parameters:
///   - privateKey: The `SecKey` representing the private key stored in the Secure Enclave.
///   - encryptionAlgorithm: The `SecKeyAlgorithm` used for the decryption. Defaults to `.eciesEncryptionCofactorX963SHA256AESGCM`.
///   - encryptedData: An array of `UInt8` representing the data to be decrypted.
/// - Returns: An optional array of `UInt8` containing the decrypted data. Returns `nil` if decryption fails.
/// - Discussion:
///   This function decrypts the provided data using the specified private key and algorithm.
///   The default encryption algorithm is `.eciesEncryptionCofactorX963SHA256AESGCM`, commonly used for secure encryption.
///   Any decryption error is logged, and the function returns `nil` in case of failure.
/// - Complexity: O(n), where `n` is the size of the data being decrypted.
/// - Author: Lee Barney
/// - Version: 0.2
func decryptWithEnclavePrivateKey(privateKey: SecKey, encryptionAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM, encryptedData: [UInt8]) -> [UInt8]? {
    // Convert the UInt8 array to Data
    let encryptedDataAsData = Data(encryptedData)
    
    var error: Unmanaged<CFError>?
    
    // Perform decryption using the private key in the Secure Enclave
    guard let decryptedData = SecKeyCreateDecryptedData(
        privateKey,
        encryptionAlgorithm,
        encryptedDataAsData as CFData,
        &error
    ) else {
        print("Decryption failed: \(error?.takeRetainedValue().localizedDescription ?? "Unknown error")")
        return nil
    }
    
    // Convert decrypted data back to [UInt8]
    return [UInt8](decryptedData as Data)
}

/// Encrypts data using a public key and an optional encryption algorithm.
/// - Parameters:
///   - publicKey: The `SecKey` representing the public key used for encryption.
///   - encryptionAlgorithm: The `SecKeyAlgorithm` specifying the algorithm to be used for encryption. Defaults to `.eciesEncryptionCofactorX963SHA256AESGCM`.
///   - dataToEncrypt: An array of `UInt8` representing the data to be encrypted.
/// - Returns: A tuple containing:
///   - `String`: A message indicating the result of the operation:
///     - `"ok"`: Encryption was successful.
///     -  A description of the error if encryption fails.
///   - `[UInt8]?`: An optional array of `UInt8` containing the encrypted data. Returns `nil` if encryption fails.
/// - Discussion:
///   This function checks if the provided encryption algorithm is supported by the given public key.
///   If the algorithm is supported, it performs encryption and returns the encrypted data as a `[UInt8]` array.
///   The default encryption algorithm is `.eciesEncryptionCofactorX963SHA256AESGCM`, which is commonly used for secure encryption.
///   In case of errors, an appropriate message and `nil` are returned.
/// - Complexity: O(n), where `n` is the size of the data being encrypted.
/// - Author: Lee Barney
/// - Version: 0.2
func encryptWithPublicKey(publicKey: SecKey, encryptionAlgorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM, dataToEncrypt: [UInt8]) -> (String,[UInt8]?) {
    // Convert the UInt8 array to Data
    let dataAsData = Data(dataToEncrypt)
    
    var error: Unmanaged<CFError>?
    
    // Check if the algorithm is supported by the public key
    guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, encryptionAlgorithm) else {
        return ("Encryption algorithm not supported by the provided key.",nil)
    }
    
    // Perform encryption using the specified algorithm
    guard let encryptedData = SecKeyCreateEncryptedData(
        publicKey,
        encryptionAlgorithm, // Use the passed algorithm
        dataAsData as CFData,
        &error
    ) else {
        let failureReason = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
        return (failureReason, nil)
    }
    
    // Convert encrypted data back to [UInt8]
    return ("ok",[UInt8](encryptedData as Data))
}




/// Retrieves a private key stored in the Secure Enclave using the specified application tag.
/// - Parameters:
///   - appTag: A `String` representing the application tag associated with the private key.
/// - Returns: A tuple containing:
///   - `String`: A message indicating the result of the operation:
///     - `"ok"`: The private key was successfully retrieved.
///     - `"Failed to retrieve private key. Status: <status>"`: The private key could not be retrieved from the keychain.
///   - `SecKey?`: An optional `SecKey` representing the private key. Returns `nil` if the key could not be retrieved.
/// - Discussion:
///   This function queries the keychain for a private key that matches the given application tag.
///   If the key is found, it returns a success message along with the private key.
///   Otherwise, it logs an appropriate error message and returns `nil`.
/// - Complexity: O(1) for the keychain query operation assuming an indexed lookup.
/// - Author: Lee Barney
/// - Version: 0.2
func getEnclavePrivateKey(appTag: String) -> (String,SecKey?) {
    let tag = appTag.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true
    ]
    
    var keyRef: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
    
    if status == errSecSuccess, let privateKey = keyRef as! SecKey? { // Use force cast or omit cast
        return ("ok",privateKey)
    } else {
        return ("Failed to retrieve private key. Status: \(status)",nil)
    }
}

/// Retrieves a public key derived from a private key stored in the Secure Enclave using the specified application tag.
/// - Parameters:
///   - appTag: A `String` representing the application tag associated with the private key.
/// - Returns: A tuple containing:
///   - `String`: A message indicating the result of the operation:
///     - `"ok"`: The public key was successfully retrieved.
///     - `"Unable to extract public key from private key."`: The private key was found, but the public key could not be extracted.
///     - `"Unable to retrieve private key. Status: <status>"`: The private key could not be retrieved from the keychain.
///   - `SecKey?`: An optional `SecKey` representing the public key. Returns `nil` if the key could not be loaded or extracted.
/// - Discussion:
///   This function queries the keychain for a private key that matches the given application tag and extracts the corresponding public key.
///   If the private key is found and the public key can be derived, it returns a success message along with the public key.
///   Otherwise, it logs an appropriate error message and returns `nil`.
/// - Complexity: O(1) for the keychain query and public key extraction assuming an indexed lookup.
/// - Author: Lee Barney
/// - Version: 0.2
func getEnclavePublicKey(appTag: String) -> (String,SecKey?) {
    let tag = appTag.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true
    ]
    
    var keyRef: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
    
    if status == errSecSuccess, let privateKey = keyRef as! SecKey? {
        // Extract the public key from the private key
        if let publicKey = SecKeyCopyPublicKey(privateKey) {
            return ("ok",publicKey)
        } else {
            return ("Unable to extract public key from private key.",nil)
        }
    }
    return("Unable to retrieve private key. Status: \(status)",nil)
}

/// Loads a public key from a specified file path, validates its format, and determines its encryption type.
/// - Parameters:
///   - path: A `String` representing the file path to the public key in DER format.
/// - Returns: A tuple containing:
///   - `encryptionType`: A `String` indicating the result of the operation or the encryption type (`"RSA"` or `"EC"`). Possible values include:
///     - `"not DER file"`: The file is not in a valid DER format.
///     - `"invalid key creation"`: The key could not be created.
///     - `"file reading error:<description>"`: An error occurred while reading the file.
///     - `"RSA"`: The key is an RSA public key.
///     - `"EC"`: The key is an Elliptic Curve public key.
///   - `publicKey`: An optional `SecKey` representing the loaded public key. Returns `nil` if the key could not be loaded or if an error occurred.
/// - Discussion:
///   This function reads public key data from the provided file path, validates that it is in DER format, and determines whether it is an RSA or EC key.
///   If the format is invalid or if key creation fails, the function returns an appropriate error message.
/// - Complexity: O(n), where `n` is the size of the key data being read and processed.
/// - Author: Lee Barney
/// - Version: 0.2
func loadPublicKey(from path: String) -> (encryptionType: String, publicKey: SecKey?) {
    do {
        // Read the key data from the specified path
        let keyData = try Data(contentsOf: URL(fileURLWithPath: path))
        
        // Validate the DER format
        guard isValidDERPublicKey(data: keyData) else {
            return ("not DER file", nil) // Failure due to invalid DER format
        }
        
        // Determine the key type by inspecting the DER data
        let isRSAKey = keyData.starts(with: [0x30]) // Adjust heuristic as needed
        
        // Define attributes for the public key
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: isRSAKey ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic
        ]
        
        // Create the SecKey object
        if let publicKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil) {
            let encryptionType = isRSAKey ? "RSA" : "EC"
            return (encryptionType, publicKey)
        } else {
            return ("invalid key creation", nil) // Failure due to invalid key creation
        }
    } catch(let error
    ) {
        return ("file reading error:\(error)", nil) // Failure due to file reading error
    }
}

/// Validates whether the provided data represents a DER-encoded public key.
/// - Parameters:
///   - data: A `Data` object containing the potential DER-encoded public key.
/// - Returns: A `Bool` indicating whether the data starts with a valid DER header:
///   - `true`: The data appears to be in valid DER format.
///   - `false`: The data does not match the expected DER structure.
/// - Discussion:
///   This function performs a basic validation by checking if the data starts with the ASN.1 SEQUENCE marker (`0x30`), which is a common header in DER-encoded public keys.
///   This heuristic does not guarantee full compliance with DER standards but provides a quick preliminary check.
/// - Complexity: O(1).
/// - Author: Lee Barney
/// - Version: 0.2
func isValidDERPublicKey(data: Data) -> Bool {
    // Check for DER structure headers
    // 0x30: ASN.1 SEQUENCE
    return data.starts(with: [0x30])
}
