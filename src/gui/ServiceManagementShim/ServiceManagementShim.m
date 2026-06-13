#include "ServiceManagementShim.h"

#include <ServiceManagement/ServiceManagement.h>
#include <stdlib.h>
#include <string.h>

static char *AVCopyCString(CFStringRef string) {
    CFIndex length = CFStringGetLength(string);
    CFIndex capacity = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    char *buffer = malloc((size_t)capacity);
    if (buffer == NULL) {
        return NULL;
    }
    if (!CFStringGetCString(string, buffer, capacity, kCFStringEncodingUTF8)) {
        free(buffer);
        return NULL;
    }
    return buffer;
}

char *AVBlessPrivilegedHelper(CFStringRef serviceName, AuthorizationRef authorization) {
    CFErrorRef error = NULL;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    Boolean blessed = SMJobBless(kSMDomainSystemLaunchd, serviceName, authorization, &error);
#pragma clang diagnostic pop

    if (blessed) {
        if (error != NULL) {
            CFRelease(error);
        }
        return NULL;
    }

    CFStringRef description = error != NULL
        ? CFErrorCopyDescription(error)
        : CFRetain(CFSTR("SMJobBless failed."));
    char *message = AVCopyCString(description);
    CFRelease(description);
    if (error != NULL) {
        CFRelease(error);
    }
    return message != NULL ? message : strdup("SMJobBless failed.");
}
