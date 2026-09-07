import Darwin
import Foundation
import Security

private typealias ValidateSealedResource = @convention(c) (
    SecStaticCode,
    CFURL,
    UInt32,
    UnsafeMutablePointer<Unmanaged<CFError>?>?
) -> OSStatus

// Resolve the private SPI dynamically and retain strict complete-bundle validation as fallback.
private let validateSealedResource: ValidateSealedResource? = {
    guard let handle = dlopen(nil, RTLD_LAZY),
          let symbol = dlsym(handle, "SecStaticCodeValidateResourceWithErrors")
    else { return nil }
    return unsafeBitCast(symbol, to: ValidateSealedResource.self)
}()

public var targetedAppResourceValidationAvailable: Bool {
    validateSealedResource != nil
}

public func validateAppBundleMainExecutable(
    _ staticCode: SecStaticCode,
    requirement: SecRequirement? = nil
) -> OSStatus {
    var information: CFDictionary?
    let informationStatus = SecCodeCopySigningInformation(staticCode, [], &information)
    guard informationStatus == errSecSuccess else { return informationStatus }
    guard let dictionary = information as? [CFString: Any],
          let executableURL = dictionary[kSecCodeInfoMainExecutable] as? URL
    else { return errSecCSInvalidObjectRef }
    return validateAppBundleResource(
        staticCode,
        resourceURL: executableURL,
        requirement: requirement
    )
}

public func validateAppBundleResource(
    _ staticCode: SecStaticCode,
    resourceURL: URL,
    requirement: SecRequirement? = nil
) -> OSStatus {
    let executableFlags = SecCSFlags(
        rawValue: kSecCSCheckAllArchitectures
            | kSecCSDoNotValidateResources
            | kSecCSStrictValidate
    )
    let executableStatus = SecStaticCodeCheckValidity(
        staticCode,
        executableFlags,
        requirement
    )
    guard executableStatus == errSecSuccess else { return executableStatus }

    guard let validateSealedResource else {
        return SecStaticCodeCheckValidity(
            staticCode,
            SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate),
            requirement
        )
    }
    return validateSealedResource(
        staticCode,
        resourceURL as CFURL,
        kSecCSStrictValidate,
        nil
    )
}
